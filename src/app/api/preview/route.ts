import { lookup } from "node:dns/promises";
import { existsSync } from "node:fs";
import { isIP } from "node:net";
import { NextRequest, NextResponse } from "next/server";
import chromium from "@sparticuz/chromium-min";
import puppeteer, { type Browser } from "puppeteer-core";
import ipaddr from "ipaddr.js";

export const runtime = "nodejs";
export const maxDuration = 45;

const chromiumArch = process.arch === "arm64" ? "arm64" : "x64";
const CHROMIUM_PACK_URL = `https://github.com/Sparticuz/chromium/releases/download/v158.0.0/chromium-v158.0.0-pack.${chromiumArch}.tar`;
const MAX_REQUESTS = 100;
const MAX_IMAGE_BYTES = 1_500_000;
const rateBuckets = new Map<string, { start: number; count: number }>();

function isPublicIp(address: string): boolean {
  try {
    return ipaddr.process(address).range() === "unicast";
  } catch {
    return false;
  }
}

async function validatePublicUrl(raw: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Invalid website address.");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("Only public HTTP and HTTPS websites are supported.");
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    throw new Error("Only standard web ports are supported.");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".test")) {
    throw new Error("Private or local network addresses are blocked.");
  }
  const directIp = isIP(host);
  const addresses = directIp ? [{ address: host }] : await lookup(host, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicIp(address))) {
    throw new Error("Private or non-public network addresses are blocked.");
  }
  return url;
}

function isRateLimited(key: string): boolean {
  const now = Date.now();
  const current = rateBuckets.get(key);
  if (!current || now - current.start >= 60_000) {
    rateBuckets.set(key, { start: now, count: 1 });
    return false;
  }
  current.count += 1;
  return current.count > 5;
}

export async function POST(request: NextRequest) {
  const clientKey = request.headers.get("x-real-ip") || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  if (isRateLimited(clientKey)) {
    return NextResponse.json({ detail: "Preview limit reached. Please wait a minute before trying again." }, { status: 429, headers: { "Retry-After": "60" } });
  }

  let stage = "request validation";
  let browser: Browser | undefined;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object") {
      return NextResponse.json({ detail: "Enter a valid website address." }, { status: 422 });
    }
    if (typeof body.url !== "string" || body.url.length > 2048) {
      return NextResponse.json({ detail: "Enter a valid website address." }, { status: 422 });
    }
    const initialUrl = body.url.includes("://") ? body.url : `https://${body.url}`;
    await validatePublicUrl(initialUrl);

    const isVercel = process.env.VERCEL === "1";
    const localCandidates = [
      process.env.CHROME_PATH,
      process.env.LOCALAPPDATA && `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
      process.env.PROGRAMFILES && `${process.env.PROGRAMFILES}\\Google\\Chrome\\Application\\chrome.exe`,
      process.env["PROGRAMFILES(X86)"] && `${process.env["PROGRAMFILES(X86)"]}\\Google\\Chrome\\Application\\chrome.exe`,
      process.env.LOCALAPPDATA && `${process.env.LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
    ].filter((candidate): candidate is string => Boolean(candidate));
    const localExecutable = localCandidates.find((candidate) => existsSync(candidate));
    if (!isVercel && !localExecutable) {
      return NextResponse.json({ detail: "Preview needs Chrome locally. Install Chrome or set CHROME_PATH to Chrome or Brave." }, { status: 503 });
    }
    stage = "starting temporary browser";
    const executablePath = isVercel ? await chromium.executablePath(CHROMIUM_PACK_URL) : localExecutable!;
    browser = await puppeteer.launch({
      args: isVercel ? chromium.args : ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
      defaultViewport: { width: 1280, height: 800, deviceScaleFactor: 1 },
      executablePath,
      headless: true,
    });
    const page = await browser.newPage();
    await page.setCacheEnabled(false);
    await page.setBypassServiceWorker(true);
    page.setDefaultNavigationTimeout(12_000);
    page.setDefaultTimeout(8_000);

    let requestCount = 0;
    await page.setRequestInterception(true);
    page.on("request", (outgoing) => {
      void (async () => {
        requestCount += 1;
        if (requestCount > MAX_REQUESTS || outgoing.resourceType() === "websocket") {
          await outgoing.abort();
          return;
        }
        const target = outgoing.url();
        const protocol = new URL(target).protocol;
        if (["data:", "blob:", "about:"].includes(protocol)) {
          await outgoing.continue();
          return;
        }
        if (protocol !== "http:" && protocol !== "https:") {
          await outgoing.abort();
          return;
        }
        await validatePublicUrl(target);
        await outgoing.continue();
      })().catch(() => outgoing.abort().catch(() => undefined));
    });

    stage = "loading website";
    try {
      await page.goto(initialUrl, { waitUntil: "domcontentloaded", timeout: 12_000 });
    } catch {
      // Some sites keep loading; capture the rendered page if the navigation timeout expires.
    }
    await new Promise((resolve) => setTimeout(resolve, 700));
    stage = "capturing screenshot";
    const image = await page.screenshot({ type: "jpeg", quality: 65, fullPage: false });
    if (image.byteLength > MAX_IMAGE_BYTES) {
      return NextResponse.json({ detail: "Preview image was too large." }, { status: 502 });
    }
    return NextResponse.json({ image: Buffer.from(image).toString("base64"), contentType: "image/jpeg" }, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "A preview could not be captured.";
    console.error("[preview] capture failed", {
      stage,
      errorName: error instanceof Error ? error.name : "UnknownError",
    });
    const status = /private|local|public|standard web|invalid website|only public/i.test(message) ? 422 : 503;
    return NextResponse.json({ detail: status === 422 ? message : "Preview unavailable. Your scan report is still ready." }, { status });
  } finally {
    await browser?.close().catch(() => undefined);
  }
}
