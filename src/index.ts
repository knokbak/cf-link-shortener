import uniqid from 'uniqid';
import hexToArrayBuffer from 'hex-to-array-buffer';

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const params = url.searchParams;

		switch (request.method) {
			case 'GET': {
				const id = url.pathname.replace('/', '');

				const value: string | null = await env.LINKS.get(id);
				if (!value) {
					return new Response(null, {
						status: 404,
					});
				}

				const found = JSON.parse(value);
				const destination = found.destination;

				return new Response(null, {
					status: 302,
					headers: {
						'Location': destination,
					},
				});
			}
			case 'POST': {
				const secret = params.get('secret');
				const link = params.get('link');
				
				if (!link) {
					return new Response(null, {
						status: 400,
					});
				}

				if (!secret) {
					return new Response(null, {
						status: 401,
					});
				}

				if (!verifySecret(secret, env.SECRET)) {
					return new Response(null, {
						status: 403,
					});
				}

				const originalId = uniqid.time();
				const idArray = new Uint8Array(hexToArrayBuffer(originalId));

				const randomArray = new Uint8Array(4);
				const randomBytes = crypto.getRandomValues(randomArray);

				const idFinal = new Uint8Array(idArray.length + randomBytes.length);
				idFinal.set(idArray, 0);
				idFinal.set(randomBytes, idArray.length);
				
				const b64encoded = bytesToBase64(idFinal).replace(/=|\+/g, '');

				const value = await env.LINKS.get(b64encoded);
				if (value) {
					return new Response(null, {
						status: 500,
					});
				}

				await env.LINKS.put(b64encoded, JSON.stringify({ destination: link }));

				return new Response(b64encoded, {
					status: 201,
				});
			}
			default: {
				return new Response(null, {
					status: 405,
				});
			}
		}
	},
} satisfies ExportedHandler<Env>;

function verifySecret (provided: string, actual: string): boolean {
	if (provided.length !== actual.length) {
		return false;
	}

	const encoder = new TextEncoder();
	const pr = encoder.encode(provided);
	const ac = encoder.encode(actual);

	if (pr.byteLength !== ac.byteLength) {
		return false;
	}

	return crypto.subtle.timingSafeEqual(pr, ac);
}

function bytesToBase64 (bytes: Uint8Array): string {
	const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join('');
	return btoa(binString);
}
