import {ACL_CATEGORY_ANY} from "../../shared/constants/permissions.mjs";

export async function queryForAllAcl(client, schema) {
    const res = await client
        .query(`select * from ${schema}.acl`);
    return res.rows;
}

export async function queryRolesForUser(client, schema, id) {
    const res = await client
        .query(`select
                        r.id as id,
                        r.name as name,
                        r.description as description
                    from ${schema}.role r
                             inner join ${schema}.user_role ur on r.id = ur.role
                             inner join ${schema}.users u on u.id = ur.user
                    where u.id = $1`, [id]);
    return res.rows;
}

export async function queryAclForUser(client, schema, id, ...categories) {
    if (categories.length === 0) {
        categories.push(ACL_CATEGORY_ANY);
    }
    const res = await client
        .query(`select
                        ${schema}.acl.id as id,
                        ${schema}.acl.name as name,
                        ${schema}.acl.resource as resource,
                        ${schema}.acl.method as method,
                        ${schema}.acl.permission as permission,
                        ${schema}.acl.category as category
                    from ${schema}.acl 
                             inner join ${schema}.role_acl ra on ${schema}.acl.id = ra.acl
                             inner join ${schema}.role r on r.id = ra.role
                             inner join ${schema}.user_role ur on r.id = ur.role
                             inner join ${schema}.users u on u.id = ur.user
                    where u.id = $1
                        and (${schema}.acl.category = ANY($2::text[]) or 
                                '*' = ANY($2::text[]) or
                                ${schema}.acl.category = '*')
                    order by ${schema}.acl.permission, ${schema}.acl.resource`, [id, categories]);
    return res.rows;
}

export async function queryAclForApiKey(client, schema, apiKeyValue, ...categories) {
    if (categories.length === 0) {
        categories.push(ACL_CATEGORY_ANY);
    }

    const res = await client
        .query(`select
                    ${schema}.acl.id as id,
                    ${schema}.acl.name as name,
                    ${schema}.acl.resource as resource,
                    ${schema}.acl.method as method,
                    ${schema}.acl.permission as permission
                from ${schema}.acl
                         inner join ${schema}.api_keys_acl aka on ${schema}.acl.id = aka.acl_id
                         inner join ${schema}.api_keys ak on aka.api_key_id = ak.id
                where ak.public_id = right($1, 36)
                    and ak.value = crypt(left($1, 36), ak.value)
                    and (${schema}.acl.category = ANY($2::text[]) or '*' = ANY($2::text[]))
                order by ${schema}.acl.permission, ${schema}.acl.resource`,
            [apiKeyValue, categories]);
    return res.rows;
}