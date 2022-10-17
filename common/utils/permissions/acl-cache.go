/*
 * Copyright (c) 2019-2021. Abstrium SAS <team (at) pydio.com>
 * This file is part of Pydio Cells.
 *
 * Pydio Cells is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pydio Cells is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Pydio Cells.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The latest code can be found at <https://pydio.com>.
 */

package permissions

import (
	"context"
	"sync"

	"github.com/pydio/cells/v4/common"
	"github.com/pydio/cells/v4/common/broker"
	"github.com/pydio/cells/v4/common/proto/idm"
	"github.com/pydio/cells/v4/common/runtime"
	"github.com/pydio/cells/v4/common/utils/cache"
)

var (
	aclCache cache.Cache
)

func initAclCache() {
	aclCache, _ = cache.OpenCache(context.TODO(), runtime.ShortCacheURL("evictionTime", "500ms", "cleanWindow", "30s"))
	_, _ = broker.Subscribe(context.TODO(), common.TopicIdmEvent, func(message broker.Message) error {
		event := &idm.ChangeEvent{}
		if _, e := message.Unmarshal(event); e != nil {
			return e
		}
		switch event.Type {
		case idm.ChangeEventType_CREATE, idm.ChangeEventType_UPDATE, idm.ChangeEventType_DELETE:
			return aclCache.Reset()
		}
		return nil
	})
}

func getAclCache() cache.Cache {
	if aclCache == nil {
		initAclCache()
	}
	return aclCache
}

type CachedAccessList struct {
	Wss             map[string]*idm.Workspace
	WssRootsMasks   map[string]map[string]Bitmask
	OrderedRoles    []*idm.Role
	WsACLs          []*idm.ACL
	FrontACLs       []*idm.ACL
	MasksByUUIDs    map[string]Bitmask
	MasksByPaths    map[string]Bitmask
	ClaimsScopes    map[string]Bitmask
	HasClaimsScopes bool
}

// cache uses the CachedAccessList struct with public fields for cache serialization
func (a *AccessList) cache(key string) error {
	a.maskBPLock.RLock()
	a.maskBULock.RLock()
	defer a.maskBPLock.RUnlock()
	defer a.maskBULock.RUnlock()
	m := &CachedAccessList{
		Wss:             a.wss,
		WssRootsMasks:   a.wssRootsMasks,
		OrderedRoles:    a.orderedRoles,
		WsACLs:          a.wsACLs,
		FrontACLs:       a.frontACLs,
		MasksByUUIDs:    a.masksByUUIDs,
		MasksByPaths:    a.masksByPaths,
		ClaimsScopes:    a.claimsScopes,
		HasClaimsScopes: a.hasClaimsScopes,
	}
	return getAclCache().Set(key, m)
}

// newFromCache looks up for a CachedAccessList struct in the cache and init an AccessList with the values.
func newFromCache(key string) (*AccessList, bool) {
	m := &CachedAccessList{}
	if b := getAclCache().Get(key, &m); !b {
		return nil, b
	}
	return &AccessList{
		maskBPLock:      &sync.RWMutex{},
		maskBULock:      &sync.RWMutex{},
		wss:             m.Wss,
		wssRootsMasks:   m.WssRootsMasks,
		orderedRoles:    m.OrderedRoles,
		wsACLs:          m.WsACLs,
		frontACLs:       m.FrontACLs,
		masksByUUIDs:    m.MasksByUUIDs,
		masksByPaths:    m.MasksByPaths,
		claimsScopes:    m.ClaimsScopes,
		hasClaimsScopes: m.HasClaimsScopes,
	}, true
}
