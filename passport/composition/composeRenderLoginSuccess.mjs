export function composeRenderLoginSuccess(logo) {
    return async (req, res) => {
        res.render('notification', {
            success: true,
            message: 'You can now safely close this window',
            title: 'Logged in',
            logo
        });
    };
}