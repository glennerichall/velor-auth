// import {getUserManager} from "../../application/utils.mjs";
//
// export const getAvatar = async (req, res) => {
//     const manager = getUserManager(req);
//     res.append('Cross-Origin-Resource-Policy', 'cross-origin');
//     const stream = await manager.getAvatarStream();
//     stream.pipe(res);
// }