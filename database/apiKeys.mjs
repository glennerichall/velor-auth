
export async function deleteApiKeyByUser(client, schema, publicId, userId) {
    const res = await client
        .query(`DELETE FROM ${schema}.api_keys 
            WHERE id IN (
                SELECT api_keys.id
                FROM ${schema}.api_keys
                INNER JOIN ${schema}.users_api_keys ON users_api_keys.api_key_id = api_keys.id
                WHERE users_api_keys.user_id = $1
                 AND api_keys.public_id = $2
            ) returning *`,
            [userId, publicId]);
    return res.rowCount === 1 ? res.rows[0] : null;
}

// export async function deleteApiKeyForValueByUser(client, schema, value, userId) {
//     const res = await client
//         .query(`DELETE FROM ${schema}.api_keys
//             WHERE id IN (
//                 SELECT api_keys.id
//                 FROM ${schema}.api_keys
//                 INNER JOIN ${schema}.users_api_keys ON users_api_keys.api_key_id = api_keys.id
//                 WHERE users_api_keys.user_id = $1
//                  AND api_keys.value = crypt($2, api_keys.value)
//             ) returning *`,
//             [userId, value]);
//     return res.rowCount === 1 ? res.rows[0] : null;
// }

export async function insertApiKey(client, schema, name) {
    const res = await client
        .query(`WITH ins AS (SELECT gen_random_uuid() AS uuid_value)
                INSERT INTO ${schema}.api_keys(value, name)
                SELECT
                    crypt(uuid_value::text, gen_salt('bf')) as value,
                    CASE
                        WHEN $1::text IS NULL THEN left(ins.uuid_value::text, 3) || '...' || right(ins.uuid_value::text, 2)
                        ELSE 
                        replace(
                        replace(
                        replace(
                        replace(
                        replace(
                        replace(
                            $1::text, 
                            '__L2__', left(ins.uuid_value::text, 2)),
                            '__L3__', left(ins.uuid_value::text, 3)),
                            '__L4__', left(ins.uuid_value::text, 4)),
                            '__R2__', right(ins.uuid_value::text, 2)),
                            '__R3__', right(ins.uuid_value::text, 3)),
                            '__R4__', right(ins.uuid_value::text, 4))
                    END AS name
                FROM ins
                RETURNING 
                    (SELECT uuid_value AS raw_uuid FROM ins), 
                    (SELECT uuid_value || '-' || public_id AS api_key FROM ins),
                    *`,
            [name]);

    return res.rowCount === 1 ? res.rows[0] : null;
}

export async function addApiKeyOwner(client, schema, apiKeyId, userId) {
    const res = await client
        .query(`insert into ${schema}.users_api_keys
                (api_key_id, user_id)
                values($1, $2)`, [apiKeyId, userId]);

    return res.rowCount === 1;
}

export async function grantAuthorization(client, schema, apiKeyId, ...aclNames) {
    const res = await client
        .query(`insert into ${schema}.api_keys_acl (api_key_id, acl_id)
                select $2 as api_key_id, id as acl_id
                from ${schema}.acl
                where name = ANY($1)`,
            [aclNames, apiKeyId]);
    return res.rowCount;
}


export async function queryApiKeyByAuth(client, schema, authId, provider) {
    const res = await client
        .query(`select ${schema}.api_keys.*
                from ${schema}.auths
                inner join ${schema}.user_auths on auths.id = user_auths.auth_id
                inner join ${schema}.users on user_auths.user_id = users.id
                inner join ${schema}.users_api_keys on users.id = users_api_keys.user_id
                inner join ${schema}.api_keys on users_api_keys.api_key_id = api_keys.id
                where auths.auth_id = $1 and auths.provider = $2`,
            [authId, provider]);
    return res.rows;
}


export async function queryApiKeyByUser(client, schema, id, userId) {
    const res = await client
        .query(`select * from ${schema}.api_keys k
                inner join ${schema}.users_api_keys u on k.id = u.api_key_id
                where u.user_id=$1
                and k.public_id=$2`,
            [userId, id]);
    return res.rowCount === 1 ? res.rows[0] : null;
}

export async function queryApiKeyForValueByUser(client, schema, value, userId) {
    const res = await client
        .query(`select * from ${schema}.api_keys k
                inner join ${schema}.users_api_keys u on k.id = u.api_key_id
                where u.user_id=$1
                and k.value=crypt(left($2,36), k.value)
                and k.public_id=right($2,36)`,
            [userId, value]);
    return res.rowCount === 1 ? res.rows[0] : null;
}

export async function queryAllApiKeysForUser(client, schema, userId) {
    const res = await client
        .query(`select * from ${schema}.api_keys k
                inner join ${schema}.users_api_keys u on k.id = u.api_key_id
                where u.user_id=$1`,
            [userId]);
    return res.rows;
}

export async function queryApiKeyByValue(client, schema, value) {
    const res = await client
        .query(`select * from ${schema}.api_keys
                where value=crypt(left($1,36),value)
                    and public_id=right($1,36)`,
            [value]);
    return res.rowCount === 1 ? res.rows[0] : null;
}