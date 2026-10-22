#!/usr/bin/env node
// Verifyd Cinematic Intro — pure Node, zero deps
// Phases: static noise → green rain → drain to white → VERIFYD emerges in cyan

const W = process.stdout.columns || 100;
const H = process.stdout.rows || 30;

const ESC = '\x1b';
const RESET = ESC + '[0m';
const HIDE  = ESC + '[?25l';
const SHOW  = ESC + '[?25h';
const CLEAR = ESC + '[2J' + ESC + '[H';

function move(r,c){ return ESC+`[${r};${c}H`; }
function fg(r,g,b){ return ESC+`[38;2;${r};${g};${b}m`; }
function bold(){ return ESC+'[1m'; }
function dim(){ return ESC+'[2m'; }

const KATAKANA = 'ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ';
const SYMBOLS  = '!@#$%^&*<>?/\\|[]{}~=+-_01';
const CHARS    = KATAKANA + SYMBOLS;

function rchar(){ return CHARS[Math.floor(Math.random()*CHARS.length)]; }
function rand(min,max){ return Math.floor(Math.random()*(max-min+1))+min; }
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// Column state for rain
const cols = Array.from({length:W}, (_,i) => ({
  x: i,
  y: rand(1, H),
  speed: rand(1,3),
  len: rand(6,18),
  chars: Array.from({length:20},()=>rchar()),
  age: rand(0,30),
  phase: 'rain',  // rain | drain | done
  drainY: H+5,
}));

function frame(tick, draining) {
  let out = '';
  for(const col of cols) {
    if(col.phase === 'done') continue;

    col.age++;
    if(col.age % col.speed !== 0) continue;

    // Shuffle chars occasionally
    if(Math.random()<0.15) col.chars[rand(0,col.chars.length-1)] = rchar();

    if(draining) {
      // Push head further down, trail fades
      col.drainY++;
      col.phase = col.drainY > H + col.len + 5 ? 'done' : 'drain';
      col.y = Math.min(col.y + col.speed, H+2);
    } else {
      col.y += col.speed;
      if(col.y - col.len > H) {
        col.y = rand(-5, 0);
        col.len = rand(6,18);
        col.speed = rand(1,3);
      }
    }

    // Draw trail
    for(let i=0; i<col.len; i++){
      const row = col.y - i;
      if(row < 1 || row > H) continue;
      const ratio = i/col.len;
      let r,g,b;
      if(i===0){
        // Head — bright white
        r=220;g=255;b=220;
      } else if(ratio < 0.2){
        // Near head — bright green
        r=0;g=255;b=70;
      } else if(ratio < 0.6){
        // Mid — green
        r=0;g=rand(150,200);b=40;
      } else {
        // Tail — dark green
        r=0;g=rand(40,90);b=20;
      }
      const c = col.chars[i % col.chars.length];
      out += move(row, col.x+1) + fg(r,g,b) + c;
    }
    // Erase below tail
    const eraseRow = col.y - col.len;
    if(eraseRow >= 1 && eraseRow <= H) {
      out += move(eraseRow, col.x+1) + ' ';
    }
  }
  return out;
}

const LOGO = [
  '██╗   ██╗███████╗██████╗ ██╗███████╗██╗   ██╗██████╗ ',
  '██║   ██║██╔════╝██╔══██╗██║██╔════╝╚██╗ ██╔╝██╔══██╗',
  '██║   ██║█████╗  ██████╔╝██║█████╗   ╚████╔╝ ██║  ██║',
  '╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝    ╚██╔╝  ██║  ██║',
  ' ╚████╔╝ ███████╗██║  ██║██║██║        ██║   ██████╔╝',
  '  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═════╝ ',
];

const TAG1 = '[ trust is not assumed. it is earned. ]';
const TAG2 = '[ VALF-1  ·  tamper-evident  ·  zero deps ]';
const TAG3 = 'by PassionCraft';

function drawLogo(alpha) {
  // alpha 0..1 — fades in cyan→white
  const logoH = LOGO.length;
  const logoW = LOGO[0].length;
  const startR = Math.floor((H - logoH - 4) / 2);
  const startC = Math.floor((W - logoW) / 2);
  let out = '';

  for(let i=0;i<LOGO.length;i++){
    const r = Math.floor(alpha * 255);
    const g = Math.floor(alpha * 255);
    const b = 255;
    out += move(startR+i, startC) + fg(r,g,b) + bold() + LOGO[i];
  }

  // Taglines
  const t1c = Math.floor((W - TAG1.length)/2);
  const t2c = Math.floor((W - TAG2.length)/2);
  const ta = Math.max(0, alpha*2 - 1); // delayed fade
  const tr = Math.floor(ta*100);
  const tg = Math.floor(ta*200);
  const tb = Math.floor(ta*255);
  out += move(startR+logoH+1, t1c) + fg(tr,tg,tb) + TAG1;
  out += move(startR+logoH+2, t2c) + fg(tr,tg,tb) + TAG2;
  // PassionCraft signature — gold, delayed, glows last
  const pa = Math.max(0, alpha*3 - 2);
  const pr = Math.floor(pa*255);
  const pg = Math.floor(pa*180);
  const pb = Math.floor(pa*30);
  const t3c = Math.floor((W - TAG3.length)/2);
  out += move(startR+logoH+4, t3c) + fg(pr,pg,pb) + bold() + TAG3 + RESET;

  // Score bar
  if(ta > 0.5) {
    const scores = '  15 ░░░░░░░░░░  DRAFT    26 ░░░░░░░░░░░░░  DRAFT    46 ░░░░░░░░░░░░░░░░░░░░  PROVISIONAL    87 ████████████████████████████████████  DEPOSITED  ';
    const sc = Math.floor((W - Math.min(scores.length, W-4))/2);
    out += move(startR+logoH+4, sc) + fg(0,180,120) + scores.slice(0, W-4);
  }

  return out;
}

async function run() {
  process.stdout.write(HIDE + CLEAR);

  // Phase 1: Rain — 80 frames
  for(let t=0;t<80;t++){
    process.stdout.write(frame(t, false));
    await sleep(40);
  }

  // Phase 2: Drain — columns fall off screen
  const drainFrames = 40;
  for(let t=0;t<drainFrames;t++){
    process.stdout.write(frame(t, true));
    // Fade in logo as rain drains
    const alpha = t/drainFrames * 0.4;
    process.stdout.write(drawLogo(alpha));
    await sleep(35);
  }

  // Phase 3: Clear residue, bring logo to full brightness
  process.stdout.write(CLEAR);
  for(let t=0;t<=30;t++){
    const alpha = t/30;
    process.stdout.write(CLEAR);
    process.stdout.write(drawLogo(alpha));
    await sleep(40);
  }

  // Phase 4: Hold 2s then hand off
  await sleep(2000);

  // Phase 5: Fade out, show CLI
  process.stdout.write(CLEAR + SHOW + RESET);

  // Print clean help after intro
  const help = require('./verifyd.cjs');
}

run().catch(e => {
  process.stdout.write(SHOW + RESET);
  console.error(e);
});