export function authenticate(req, res, next) {
    let strategy = req.authStrategy;
    return strategy.authenticate(req, res, next);
}