export class RuntimeCoreError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'RuntimeCoreError';
        this.code = code;
    }
}
export function formatAjvErrors(errors) {
    if (!errors?.length) {
        return [];
    }
    return errors.map((error) => ({
        instancePath: error.instancePath,
        keyword: error.keyword,
        message: error.message,
        params: error.params
    }));
}
//# sourceMappingURL=errors.js.map