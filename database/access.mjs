export async function queryForAllAccess(client, schema) {
    const res = await client
        .query(`select * from ${schema}.access`);
    return res.rows;
}

export async function insertAccess(client, schema, {
    ip,
    url,
    method,
    fingerprint,
    frontend,
    userId,
    loggedIn
}) {
    const res = await client
        .query(`insert into ${schema}.access
                        (fingerprint, ip, resource, method, bv, fv, user_id, logged_in)
                    values ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [fingerprint, ip, url, method,
                process.env.ZUPFE_VERSION, frontend, userId, loggedIn]);

    return res.rowCount === 1;
}