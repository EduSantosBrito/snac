export interface ISSHConnection {
    connect(params: ISSHConnectionParams): Promise<any>;
}

export interface ISSHConnectionParams {
    host: String;
    username: String;
    port: Number;
    privateKey: String;
    passphrase: String;
}

export interface IIPChecker {
    checkIpsFromSSH(sshParams: ISSHConnectionParams, abuseipdbKey: String, hetrixToolsKey?: String): Promise<IIPReport[]>;
}

interface IBlackListItem {
    rbl: String;
    delist: String;
}

export interface IIPReport {
    ipAddress: String;
    isPublic: Boolean;
    ipVersion: Number;
    isWhitelisted: Boolean;
    abuseConfidenceScore: Number;
    countryCode: String;
    usageType: String;
    isp: String;
    domain: String;
    totalReports: Number;
    numDistinctUsers: Number;
    lastReportedAt: String;
    blacklistedOn: IBlackListItem[];
}
