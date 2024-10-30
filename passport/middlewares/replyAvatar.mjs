export const replyAvatar = async (req, res) => {
    const manager = getProfileManager(req);
    res.append('Cross-Origin-Resource-Policy', 'cross-origin');
    const stream = await manager.getAvatarStream();
    if (stream !== null) {
        stream.pipe(res);
    } else {
        res.sendStatus(404);
    }
};