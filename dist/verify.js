import { jwtVerify } from 'jose';
export async function verifyOvid(jwt, issuerPublicKey, options) {
    try {
        const { payload } = await jwtVerify(jwt, issuerPublicKey, {
            algorithms: ['EdDSA'],
        });
        const claims = payload;
        // Check ovid_version
        if (claims.ovid_version !== 1) {
            return invalid();
        }
        const now = Math.floor(Date.now() / 1000);
        const expiresIn = claims.exp - now;
        if (expiresIn <= 0) {
            return invalid();
        }
        return {
            valid: true,
            principal: claims.sub,
            role: claims.role,
            scope: claims.scope,
            chain: claims.parent_chain,
            expiresIn,
        };
    }
    catch {
        return invalid();
    }
}
function invalid() {
    return {
        valid: false,
        principal: '',
        role: '',
        scope: {},
        chain: [],
        expiresIn: 0,
    };
}
