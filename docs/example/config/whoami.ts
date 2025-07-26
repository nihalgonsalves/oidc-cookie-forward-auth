export const config = {
	getUpstreamCookies: () =>
		fetch(new URL("http://whoami:80/auth/signin"), {
			method: "POST",
			body: new URLSearchParams({
				username: "admin",
				password: "password",
			}),
		}),
	validateUpstreamSession: async (headers: Bun.HeadersInit) => {
		try {
			const response = await fetch(new URL("http://whoami:80/me"), {
				headers,
				redirect: "manual",
			});

			return response.ok;
		} catch {
			return false;
		}
	},
};
