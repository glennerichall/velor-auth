export function composeInsertUser(queryForUserByAuthId, queryForAuthsByUserId,
                            insertUser, grantUserRole, linkAuthToUSer) {

    return async (auth) => {
        let user = await queryForUserByAuthId(auth.id);
        if (user === null) {
            user = await insertUser(auth);

            // everyone is a normal user
            await grantUserRole(user.id, 'normal');
        }

        await linkAuthToUSer(user.id, auth.id);
        user.auths = await queryForAuthsByUserId(user.id);
        user.loginAuth = auth;
        return user;
    };
}