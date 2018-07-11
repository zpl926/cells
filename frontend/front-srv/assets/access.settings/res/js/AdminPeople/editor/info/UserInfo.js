import React from 'react'
import Pydio from 'pydio'
import User from '../model/User'
import {IconMenu, IconButton, MenuItem} from 'material-ui';
const {FormPanel} = Pydio.requireLib('form');
import UserRolesPicker from '../user/UserRolesPicker'

class UserInfo extends React.Component {

    constructor(props){
        super(props);
        this.state = {
            parameters: []
        };
        AdminComponents.PluginsLoader.getInstance(props.pydio).formParameters('//global_param[contains(@scope,"user")]|//param[contains(@scope,"user")]').then(params => {
            this.setState({parameters: params});
        })

    }

    getPydioRoleMessage(messageId){
        const {pydio} = this.props;
        return pydio.MessageHash['role_editor.' + messageId] || messageId;
    }

    onParameterChange(paramName, newValue, oldValue){
        const {user} = this.props;
        const {parameters} = this.state;
        const params = parameters.filter(p => p.name === paramName);
        const idmUser = user.getIdmUser();
        const role = user.getRole();
        // do something
        console.log(paramName, newValue);
        if(paramName === 'displayName' || paramName === 'email' || paramName === 'profile'){
            idmUser.Attributes[paramName] = newValue;
        } else if (params.length && params[0].aclKey) {
            role.setParameter(params[0].aclKey, newValue);
        }
    }

    buttonCallback(action){
        if(action === "update_user_pwd"){
            this.props.pydio.UI.openComponentInModal('AdminPeople', 'UserPasswordDialog', {userId: userId});
        }else{
            this.toggleUserLock(userId, locked, action);
        }
    }

    toggleUserLock(userId, currentLock, buttonAction){
        var reqParams = {
            get_action:"edit",
            sub_action:"user_set_lock",
            user_id : userId
        };
        if(buttonAction == "user_set_lock-lock"){
            reqParams["lock"] = (currentLock.indexOf("logout") > -1 ? "false" : "true");
            reqParams["lock_type"] = "logout";
        }else{
            reqParams["lock"] = (currentLock.indexOf("pass_change") > -1 ? "false" : "true");
            reqParams["lock_type"] = "pass_change";
        }
        PydioApi.getClient().request(reqParams, function(transport){
            this.loadRoleData();
        }.bind(this));

    }

    render(){

        const {user, pydio} = this.props;
        const {parameters} = this.state;
        if(!parameters){
            return <div>Loading...</div>;
        }

        // Load user-scope parameters
        let values = {
            profiles:[],
        }, locks = '';
        let rolesPicker;
        if(user){
            // Compute values
            const idmUser = user.getIdmUser();
            const role = user.getRole();
            console.log(idmUser.Roles);
            rolesPicker = (
                <UserRolesPicker
                    roles={idmUser.Roles}
                    loadingMessage={'Loading Roles...'}
                    addRole={(r) => user.addRole(r)}
                    removeRole={(r) => user.removeRole(r)}
                    switchRoles={(r1,r2) => user.switchRoles(r1,r2)}
                />
            );

            const attributes = idmUser.Attributes || {};
            values = {
                ...values,
                displayName: attributes['displayName'],
                email: attributes['email'],
                profile: attributes['profile'],
                login: idmUser.Login
            };
            parameters.map(p => {
                if(p.aclKey && role.getParameterValue(p.aclKey)){
                    values[p.name] = role.getParameterValue(p.aclKey);
                }
            });

        }
        const params = [
            {name:"login", label:this.getPydioRoleMessage('21'),description:pydio.MessageHash['pydio_role.31'],"type":"string", readonly:true},
            {name:"profile", label:this.getPydioRoleMessage('22'), description:pydio.MessageHash['pydio_role.32'],"type":"select", choices:'admin|Administrator,standard|Standard,shared|Shared'},
            ...parameters
        ];

        return (
            <div>
                <h3 className={"paper-right-title"} style={{display:'flex', alignItems: 'center'}}>
                    <div style={{flex:1}}>
                        {pydio.MessageHash['pydio_role.24']}
                        <div className={"section-legend"}>{pydio.MessageHash['pydio_role.54']}</div>
                    </div>
                    <IconMenu
                        iconButtonElement={<IconButton iconClassName={"mdi mdi-dots-vertical"}/>}
                        anchorOrigin={{horizontal: 'right', vertical: 'top'}}
                        targetOrigin={{horizontal: 'right', vertical: 'top'}}
                        tooltip={"Actions"}
                    >
                        <MenuItem primaryText={this.getPydioRoleMessage('25')} onTouchTap={() => this.buttonCallback('update_user_pwd')}/>
                        <MenuItem primaryText={this.getPydioRoleMessage((locks.indexOf('logout') > -1?'27':'26'))} onTouchTap={() => this.buttonCallback('user_set_lock-lock')}/>
                        <MenuItem primaryText={this.getPydioRoleMessage((locks.indexOf('pass_change') > -1?'28b':'28'))} onTouchTap={() => this.buttonCallback('user_set_lock-pass_change')}/>
                    </IconMenu>
                </h3>
                <FormPanel
                    parameters={params}
                    onParameterChange={this.onParameterChange.bind(this)}
                    values={values}
                    depth={-2}
                />
                {rolesPicker}
            </div>
        );


    }

}

UserInfo.PropTypes = {
    pydio: React.PropTypes.instanceOf(Pydio).isRequired,
    pluginsRegistry: React.PropTypes.instanceOf(XMLDocument),
    user: React.PropTypes.instanceOf(User),
};

export {UserInfo as default}