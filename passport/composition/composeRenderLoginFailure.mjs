export function composeRenderLoginFailure(logo) {
    return async (req, res) => {
        res.render('notification', {
            success: false,
            message: req.flash("error"),
            title: 'Failed to login',
            logo
        });
    }
}