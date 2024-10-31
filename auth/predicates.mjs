import {allAsync} from "velor/utils/predicates.mjs";

export const isAuthenticated = async req => req.isAuthenticated();

export const isSessionValid = async req => !req.sessionError;

export const isCsrfTokenValid = async req => {
    const csrf = req.header('X-Csrf-Token');
    return csrf === req.userSession.csrf;
};

export const isSessionValidAndAuthenticated = allAsync(
    isSessionValid,
    isAuthenticated);