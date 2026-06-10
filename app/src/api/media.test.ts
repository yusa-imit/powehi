import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MediaModule from "./media";

const { requestMediaUpload, confirmMediaUpload, getMediaDownloadUrl, deleteMedia } = MediaModule;

describe("media API", () => {
	let fetchSpy: MockInstance<typeof globalThis.fetch>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch");
	});

	afterEach(() => {
		fetchSpy.mockRestore();
	});

	describe("requestMediaUpload", () => {
		it("POSTs to /v1/media/upload-url with content_type and size_bytes", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(
					JSON.stringify({ mediaId: "abc-123", uploadUrl: "https://r2.example.com/put" }),
					{
						status: 200,
					},
				),
			);

			const result = await requestMediaUpload("tok", "image/jpeg", 1024);

			expect(fetchSpy).toHaveBeenCalledWith("/v1/media/upload-url", {
				method: "POST",
				headers: expect.objectContaining({
					"Content-Type": "application/json",
					Authorization: "Bearer tok",
				}),
				body: JSON.stringify({ content_type: "image/jpeg", size_bytes: 1024 }),
			});
			expect(result).toEqual({ mediaId: "abc-123", uploadUrl: "https://r2.example.com/put" });
		});

		it("includes group_id when provided", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ mediaId: "xyz", uploadUrl: "https://r2.example.com/put2" }), {
					status: 200,
				}),
			);

			await requestMediaUpload("tok", "image/png", 2048, "group-uuid-abc");

			const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
			const body = JSON.parse(init.body as string) as Record<string, unknown>;
			expect(body.group_id).toBe("group-uuid-abc");
		});

		it("omits group_id when not provided", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ mediaId: "xyz", uploadUrl: "https://r2.example.com/put3" }), {
					status: 200,
				}),
			);

			await requestMediaUpload("tok", "video/mp4", 512000);

			const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
			const body = JSON.parse(init.body as string) as Record<string, unknown>;
			expect(Object.prototype.hasOwnProperty.call(body, "group_id")).toBe(false);
		});

		it("Bearer token is in Authorization header, not URL", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ mediaId: "x", uploadUrl: "https://r2.example.com/u" }), {
					status: 200,
				}),
			);

			await requestMediaUpload("secret-media-token", "image/jpeg", 100);

			const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
			expect(url).not.toContain("secret-media-token");
			const headers = init.headers as Record<string, string>;
			expect(headers.Authorization).toBe("Bearer secret-media-token");
		});

		it("throws on non-2xx (returns error code from body)", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ code: "size_out_of_range" }), { status: 400 }),
			);

			await expect(requestMediaUpload("tok", "image/jpeg", 0)).rejects.toThrow("size_out_of_range");
		});

		it("throws with http_N when body has no code", async () => {
			fetchSpy.mockResolvedValueOnce(new Response("{}", { status: 401 }));

			await expect(requestMediaUpload("bad-tok", "image/jpeg", 100)).rejects.toThrow("http_401");
		});
	});

	describe("confirmMediaUpload", () => {
		it("POSTs to /v1/media/:id/confirm with Bearer token", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

			await confirmMediaUpload("tok", "media-id-456");

			expect(fetchSpy).toHaveBeenCalledWith("/v1/media/media-id-456/confirm", {
				method: "POST",
				headers: expect.objectContaining({ Authorization: "Bearer tok" }),
			});
		});

		it("Bearer token not in URL", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

			await confirmMediaUpload("confirm-tok", "media-789");

			const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
			expect(url).not.toContain("confirm-tok");
		});

		it("throws on unauthorized (401)", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ code: "unauthorized" }), { status: 401 }),
			);

			await expect(confirmMediaUpload("bad-tok", "media-id")).rejects.toThrow("unauthorized");
		});
	});

	describe("getMediaDownloadUrl", () => {
		it("GETs /v1/media/:id/download-url and returns downloadUrl", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ downloadUrl: "https://r2.example.com/get-abc" }), {
					status: 200,
				}),
			);

			const result = await getMediaDownloadUrl("tok", "media-abc");

			expect(fetchSpy).toHaveBeenCalledWith("/v1/media/media-abc/download-url", {
				headers: expect.objectContaining({ Authorization: "Bearer tok" }),
			});
			expect(result).toEqual({ downloadUrl: "https://r2.example.com/get-abc" });
		});

		it("Bearer token is in Authorization header, not URL", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ downloadUrl: "https://r2.example.com/g" }), { status: 200 }),
			);

			await getMediaDownloadUrl("download-token", "media-xyz");

			const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
			expect(url).not.toContain("download-token");
			const headers = init.headers as Record<string, string>;
			expect(headers.Authorization).toBe("Bearer download-token");
		});

		it("throws on unauthorized (401)", async () => {
			fetchSpy.mockResolvedValueOnce(new Response("{}", { status: 401 }));

			await expect(getMediaDownloadUrl("bad-tok", "media-id")).rejects.toThrow("http_401");
		});
	});

	describe("deleteMedia", () => {
		it("sends DELETE to /v1/media/:id with Bearer token", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

			await deleteMedia("tok", "media-del-123");

			expect(fetchSpy).toHaveBeenCalledWith("/v1/media/media-del-123", {
				method: "DELETE",
				headers: expect.objectContaining({ Authorization: "Bearer tok" }),
			});
		});

		it("Bearer token is in Authorization header, not URL", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

			await deleteMedia("del-token", "media-to-delete");

			const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
			expect(url).not.toContain("del-token");
		});

		it("resolves on 204", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

			await expect(deleteMedia("tok", "media-id")).resolves.toBeUndefined();
		});

		it("throws on error response", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ code: "not_found" }), { status: 404 }),
			);

			await expect(deleteMedia("tok", "missing-media")).rejects.toThrow("not_found");
		});
	});
});
