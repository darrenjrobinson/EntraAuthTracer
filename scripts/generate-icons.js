const { Jimp, intToRGBA, rgbaToInt } = require('jimp');
const path = require('path');

const SOURCE = path.join(__dirname, '../icons/EntraAuthTracer.png');
const SIZES = [16, 32, 48, 128];
const TRANSPARENT = rgbaToInt(0, 0, 0, 0);

function isNearWhite({ r, g, b }) {
  return r > 220 && g > 220 && b > 220;
}

async function removeWhiteBackground(img) {
  const { width, height } = img.bitmap;
  const visited = new Uint8Array(width * height);
  const queue = [];

  const seed = (x, y) => {
    if (x < 0 || x >= width || y < 0 || y >= height) return;
    const i = y * width + x;
    if (visited[i]) return;
    visited[i] = 1;
    const rgba = intToRGBA(img.getPixelColor(x, y));
    if (isNearWhite(rgba)) queue.push(x, y);
  };

  seed(0, 0);
  seed(width - 1, 0);
  seed(0, height - 1);
  seed(width - 1, height - 1);

  let qi = 0;
  while (qi < queue.length) {
    const x = queue[qi++];
    const y = queue[qi++];
    img.setPixelColor(TRANSPARENT, x, y);
    seed(x + 1, y);
    seed(x - 1, y);
    seed(x, y + 1);
    seed(x, y - 1);
  }

  return img;
}

async function main() {
  console.log('Loading source: ' + SOURCE);
  const source = await Jimp.read(SOURCE);
  console.log('Source size: ' + source.bitmap.width + 'x' + source.bitmap.height);
  console.log('Removing white background (flood fill from corners)...');
  await removeWhiteBackground(source);

  for (const size of SIZES) {
    const dest = path.join(__dirname, '../icons/icon' + size + '.png');
    await source.clone().resize({ w: size, h: size }).write(dest);
    console.log('  OK icon' + size + '.png');
  }
  console.log('Done!');
}

main().catch(err => { console.error('Error:', err.message); process.exit(1); });
