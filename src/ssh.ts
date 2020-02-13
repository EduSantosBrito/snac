import NodeSSH from 'node-ssh';
/// <reference path="./index.d.ts" />
import { ISSHConnection, ISSHConnectionParams } from '.';

class SSHConnection implements ISSHConnection {
    connect(params: ISSHConnectionParams): Promise<{ exec: (command: String, parameter?: any[]) => Promise<any> }> {
        return NodeSSH.connect(params);
    }
}

export default SSHConnection;
