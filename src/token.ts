import Shuttle from "@cch137/shuttle/index.js";

export type AuthClientSession = {
  sid: string;
  uid?: string;
  name?: string;
};

function base64UrlToUint8Array(base64Url: string) {
  const binaryString = atob(
    base64Url.replace(/-/g, "+").replace(/_/g, "/") +
      "====".substring(base64Url.length % 4)
  );
  return new Uint8Array(binaryString.length).map((v, i) =>
    binaryString.charCodeAt(i)
  );
}

function uint8ArrayToBase64Url(uint8Array: Uint8Array) {
  return btoa([...uint8Array].map((v) => String.fromCharCode(v)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function parseToken(
  token: string,
  salts: number[] = []
): AuthClientSession | null {
  try {
    const { sid, uid, name } = Shuttle.parse<AuthClientSession>(
      base64UrlToUint8Array(token),
      { salts, md5: true }
    );
    if (typeof sid !== "string") return null;
    if (uid !== undefined && typeof uid !== "string") return null;
    if (name !== undefined && typeof name !== "string") return null;
    return { sid, uid, name };
  } catch {}
  return null;
}

export function serializeToken(
  token: AuthClientSession,
  salts: number[] = []
): string {
  return uint8ArrayToBase64Url(Shuttle.serialize(token, { salts, md5: true }));
}
