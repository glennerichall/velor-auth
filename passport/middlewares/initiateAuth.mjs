import {URL_PASSPORT_CALLBACK} from "../../routes/urls.mjs";

export function initiateAuth(req, res, next) {
    let strategy = req.authStrategy;
    if (!strategy.initialized) {
        strategy.initialize(getFullHostUrls(req)[URL_PASSPORT_CALLBACK]);
    }
    return strategy.initiate(req, res, next);
}