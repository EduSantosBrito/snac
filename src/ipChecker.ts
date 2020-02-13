import fetch from 'isomorphic-fetch';
import SSHConnection from './ssh';
/// <reference path="./index.d.ts" />
import { IIPChecker, ISSHConnectionParams, IIPReport } from '.';

class IPChecker implements IIPChecker {
    async checkIpsFromSSH(sshParams: ISSHConnectionParams, abuseipdbKey: String, hetrixToolsKey?: String): Promise<IIPReport[]> {
        const sshConnection = await new SSHConnection().connect(sshParams);
        const ipsWithPort: String = await sshConnection.exec("netstat -ano | grep ESTAB | awk '{print $5}'", []);
        const ips = ipsWithPort
            .split('\n')
            .filter(ip => ip)
            .map(ip => ip.split(':')[0])
            .filter(
                ip =>
                    /^(\25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(
                        ip,
                    ) && !this.isPrivateIP(ip),
            );
        return this.getRiskIps(ips, abuseipdbKey, hetrixToolsKey);
    }

    private async getRiskIps(ips: string[], abuseipdbKey: String, hetrixToolsKey?: String): Promise<IIPReport[]> {
        const riskIps: IIPReport[] = [];
        await Promise.all(
            ips.map(async ip => {
                const { data } = await (
                    await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
                        method: 'GET',
                        headers: {
                            'Content-Type': 'application/json',
                            Key: `${abuseipdbKey}`,
                        },
                    })
                ).json();
                if (data.abuseConfidenceScore > 0) {
                    // eslint-disable-next-line camelcase
                    const { blacklisted_on } = await (
                        await fetch(`https://api.hetrixtools.com/v2/${hetrixToolsKey}/blacklist-check/ipv4/${ip}/`, {
                            method: 'GET',
                        })
                    ).json();
                    riskIps.push({ ...data, blacklistedOn: blacklisted_on });
                }
            }),
        );
        return riskIps;
    }

    isPrivateIP(ip: String) {
        const parts = ip.split('.');
        return (
            parts[0] === '10' ||
            (parts[0] === '172' && parseInt(parts[1], 10) >= 16 && parseInt(parts[1], 10) <= 31) ||
            (parts[0] === '192' && parts[1] === '168') ||
            parts[0] === '127'
        );
    }
}

export default IPChecker;
