export async function createToken(client, schema, authId, token) {
    const res = await client
        .query(`insert into ${schema}.auth_tokens (auth_id, expiration, value)
                    values ($1, $2, $3)`,
            [authId, token.expiration, token.value]);
    return res.rowCount;
}

export async function queryTokensForAuth(client, schema, authId) {
    const res = await client
        .query(`select *
                    from ${schema}.auth_tokens
                    where auth_id = $1`,
            [authId]);
    return res.rows;
}

export async function deleteToken(client, schema, tokenId) {
    const res = await client
        .query(`delete
                    from ${schema}.auth_tokens
                    where id = $1`,
            [tokenId]);
    return res.rowCount;
}

export async function deleteTokensForUser(client, schema, authId) {
    const res = await client
        .query(`delete
                    from ${schema}.auth_tokens
                    where auth_id = $1`,
            [authId]);
    return res.rowCount;
}
