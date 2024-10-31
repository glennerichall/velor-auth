export async function queryAuthById(client, schema, id) {
    const res = await client
        .query(`select *
                    from ${schema}.auths
                    where id = $1`,
            [id]);
    if (res.rows.length === 1) {
        return res.rows[0];
    }
    return null;
}

export async function queryByAuthIdProvider(client, schema, auth, provider) {
    const res = await client
        .query(`select *
                    from ${schema}.auths
                    where auth_id = $1
                      and provider = $2`,
            [auth, provider]);
    if (res.rows.length === 1) {
        return res.rows[0];
    }
    return null;
}

export async function insertAuth(client, schema, auth) {
    const res = await client
        .query(`insert into ${schema}.auths
                    (auth_id, provider, email, verified,
                     displayName, lastName, firstName, avatar)
                    values ($1, $2, $3, $4, $5, $6, $7, $8) returning id`,
            [
                auth.auth_id,
                auth.provider,
                auth.email,
                auth.verified,
                auth.displayName,
                auth.lastName,
                auth.firstName,
                auth.avatar
            ]);
    return res.rows[0].id;
}