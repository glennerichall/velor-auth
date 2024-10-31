export function getFingerprint(req) {
    return req.header('x-fpu') || req.query.fpu;
}