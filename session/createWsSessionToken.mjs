import {getDatabase} from "../../../backend/application/services/backendServices.mjs";

export const createWsSessionToken = async (req, res) => {
    const database = getDatabase(req);
    if (!req.requestDetails || !req.requestDetails.csrf) {
        res.sendStatus(422);
        return;
    }
    const token = await database.tokens.createToken(2, {csrf: req.requestDetails.csrf});
    res.status(201).send({token:token.value});
};