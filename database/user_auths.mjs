
export async function insertOrNothing(client, schema, userId, authId) {
    const res = await client
        .query(`insert into ${schema}.user_auths
                        (user_id, auth_id)
                    values ($1, $2)
                    on conflict do nothing`,
            [userId, authId]);
    return res.rowCount;
}


export async function queryForPrimaryAuthForUserId(client, schema, userId) {
    const res = await client
        .query(`select a.id,
                           provider,
                           email,
                           verified,
                           displayName,
                           firstName,
                           lastName,
                           avatar
                    from ${schema}.auths a
                             inner join ${schema}.users u on a.id = u.primary_auth_id
                    where u.user_id = $1
                      and a.active = true`,
            [userId]);
    return res.rows;
}


export async function queryForAuthsByUserId(client, schema, userId) {
    const res = await client
        .query(`select a.id,
                           provider,
                           email,
                           verified,
                           displayName,
                           firstName,
                           lastName,
                           avatar
                    from ${schema}.auths a
                             inner join ${schema}.user_auths ua on a.id = ua.auth_id
                    where ua.user_id = $1
                      and a.active = true`,
            [userId]);
    return res.rows;
}


export async function queryForUserByAuthId(client, schema, authId) {
    const res = await client
        .query(`select u.id, primary_auth_id, active
                    from ${schema}.users u
                             inner join ${schema}.user_auths ua on u.id = ua.user_id
                    where ua.auth_id = $1`,
            [authId]);
    if (res.rows.length === 1) {
        return res.rows[0];
    }
    return null;
}
