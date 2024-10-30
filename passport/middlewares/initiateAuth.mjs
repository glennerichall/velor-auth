export function initiateAuth(req, res, next) {
    let strategy = req.authStrategy;
    return strategy.initiate(req, res, next);
}