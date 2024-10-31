
export async function queryForUserById(client, schema, userId) {
    const res = await client
        .query(`select *
                    from ${schema}.users
                    inner join ${schema}.auths on auths.id = users.primary_auth_id
                    where users.id = $1`
            , [userId]);
    if (res.rows.length === 1) {
        return res.rows[0];
    }
    return null;
}

export async function queryByLastFingerprint(client, schema, fp) {
    const res = await client
        .query(`select *
                    from ${schema}.logins
                    where fingerprint = $1
                    order by date desc
                    limit 1`, [fp]);
    if (res.rows.length === 1) {
        return res.rows[0].user_id;
    }
    return null;
}


export async function queryByPrimaryAuth(client, schema, auth, provider) {
    const res = await client
        .query(`select ${schema}.users.*
                    from ${schema}.users
                    inner join ${schema}.auths a on a.id = users.primary_auth_id
                    where a.auth_id = $1
                      and a.provider = $2`
            , [auth, provider]);
    if (res.rows.length === 1) {
        return res.rows[0];
    }
    return null;
}

export async function updateUserVerifiedEmail(client, schema, id) {
    const res = await client
        .query(`update ${schema}.auths
                    set verified= true
                    where id = $1`, [id]);
    if (res.rows.length === 1) {
        return res.rows[0];
    }
}

export async function insertUser(client, schema, auth) {
    const res = await client
        .query(`insert into ${schema}.users (primary_auth_id)
                    values ($1)
                    returning *`,
            [
                auth.id,
            ]);
    if (res.rowCount === 1) {
        return res.rows[0];
    }
    return null;
}

export async function queryForLastLogin(client, schema, userId) {
    const res = await client.query(`
                    select logins.id, ip, date, fingerprint
                    from ${schema}.user_auths
                             inner join ${schema}.logins
                                        on logins.auth_id = user_auths.auth_id
                    where user_id = $1
                      and type = 'login'
                    order by date desc
                    limit 2`,
        [userId]);
    return res.rows;
}

export async function insertLoginEvent(client, schema, fingerprint, auth_id, ip, type = 'login') {
    const res = await client
        .query(`insert into ${schema}.logins (fingerprint, auth_id, ip, type)
                    values ($1, $2, $3, $4)`,
            [
                fingerprint, auth_id, ip, type
            ]);
    return res.rowCount === 1;
}

export async function grantUserRoleByAuth(client, schema, authName, provider, roleName) {
    await client.query(`
        insert into ${schema}.user_role (role, "user")
        values (
            (select id from ${schema}.role where name = $1),
            (select users.id from ${schema}.users
                inner join ${schema}.auths a on a.id = users.primary_auth_id
                where a.auth_id = $2 and a.provider= $3))`,
        [roleName, authName, provider]);
}

export async function queryForUserByApiKey(client, schema, apiKey) {
    const result = await client.query(`
        select ${schema}.users.* 
        from ${schema}.api_keys
        inner join ${schema}.users_api_keys on users_api_keys.api_key_id = api_keys.id
        inner join ${schema}.users on users_api_keys.user_id = users.id
        where api_keys.value=crypt(left($1,36), api_keys.value)
            and api_keys.public_id=right($1,36)`,
        [apiKey]);

    return result.rowCount === 1 ? result.rows[0] : null;
}

export async function grantUserRole(client, schema, userId, roleName) {
    await client.query(`
        insert into ${schema}.user_role (role, "user")
        values (
            (select id from ${schema}.role where name = $1),
            $2)`,
        [roleName, userId]);
}

export async function revokeUserRole(client, schema, authName, provider, roleName) {
    await client.query(`
        delete from ${schema}.user_role
        where role in (select id from ${schema}.role where name = $1)
        and "user" in (select users.id from ${schema}.users
                inner join ${schema}.auths a on a.id = users.primary_auth_id
                where a.auth_id = $2 and a.provider= $3)`,
        [roleName, authName, provider]);
}