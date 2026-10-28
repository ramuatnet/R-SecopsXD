/**
 * Minimal PDF 1.4 writer — no external dependencies.
 * Core Type1 Helvetica fonts, uncompressed content streams, correct xref
 * offsets. Layout is deliberately simple: flowing text with wrapping,
 * horizontal rules, badge-like labels as text.
 */
const PAGE_W = 595.28; // A4
const PAGE_H = 841.89;
const MARGIN = 56;
const CONTENT_W = PAGE_W - MARGIN * 2;

// Approximate Helvetica advance widths (1/1000 em) for wrapping estimates.
const WIDTHS: Record<string, number> = { ' ': 278 };
const DEFAULT_W = 556;

function charWidth(ch: string, size: number, bold: boolean): number {
  if (WIDTHS[ch] !== undefined) return (WIDTHS[ch]! * size) / 1000;
  const wide = /[mwMW@]/.test(ch) ? 880 : /[iljI|!.,;:'`]/.test(ch) ? 250 : /[ftrFTT()\[\]\/\\-]/.test(ch) ? 360 : /[A-Z]/.test(ch) ? 680 : DEFAULT_W;
  return (wide * (bold ? 1.06 : 1) * size) / 1000;
}

function textWidth(s: string, size: number, bold: boolean): number {
  let w = 0;
  for (const ch of s) w += charWidth(ch, size, bold);
  return w;
}

export function wrapText(text: string, size: number, maxWidth: number, bold = false): string[] {
  const lines: string[] = [];
  for (const paragraph of text.split('\n')) {
    const words = paragraph.split(/\s+/).filter(Boolean);
    if (words.length === 0) {
      lines.push('');
      continue;
    }
    let line = '';
    for (const word of words) {
      const candidate = line === '' ? word : `${line} ${word}`;
      if (textWidth(candidate, size, bold) <= maxWidth) {
        line = candidate;
      } else {
        if (line !== '') lines.push(line);
        // hard-split absurdly long words (URLs)
        let rest = word;
        while (textWidth(rest, size, bold) > maxWidth) {
          let cut = rest.length;
          while (cut > 1 && textWidth(rest.slice(0, cut), size, bold) > maxWidth) cut--;
          lines.push(rest.slice(0, cut));
          rest = rest.slice(cut);
        }
        line = rest;
      }
    }
    if (line !== '') lines.push(line);
  }
  return lines;
}

function pdfEscape(s: string): string {
  return s
    .replace(/[\u0080-\uFFFF]/g, '?')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/\r/g, '');
}

interface TextOp { x: number; y: number; size: number; bold: boolean; text: string }
interface RuleOp { x1: number; y1: number; x2: number; y2: number; gray: number; width: number }
interface RectOp { x: number; y: number; w: number; h: number; gray: number }

export class PdfBuilder {
  private ops: Array<TextOp | RuleOp | RectOp> = [];
  private cursorY = PAGE_H - MARGIN;
  readonly pages: Array<Array<TextOp | RuleOp | RectOp>> = [];

  private newPage(): void {
    if (this.ops.length > 0) this.pages.push(this.ops);
    this.ops = [];
    this.cursorY = PAGE_H - MARGIN;
  }

  ensureSpace(height: number): void {
    if (this.cursorY - height < MARGIN + 20) this.newPage();
  }

  moveDown(dy: number): void {
    this.cursorY -= dy;
  }

  text(text: string, opts: { size?: number; bold?: boolean; gray?: number; indent?: number; leading?: number } = {}): void {
    const size = opts.size ?? 10;
    const bold = opts.bold ?? false;
    const indent = opts.indent ?? 0;
    const leading = opts.leading ?? size * 1.45;
    const lines = wrapText(text, size, CONTENT_W - indent, bold);
    for (const line of lines) {
      this.ensureSpace(leading);
      this.ops.push({ x: MARGIN + indent, y: this.cursorY - size, size, bold, text: line });
      this.cursorY -= leading;
    }
  }

  rule(gray = 0.8, width = 0.7, gap = 8): void {
    this.ensureSpace(gap + 2);
    this.ops.push({ x1: MARGIN, y1: this.cursorY, x2: PAGE_W - MARGIN, y2: this.cursorY, gray, width });
    this.cursorY -= gap;
  }

  label(text: string, color: 'dark' | 'red' | 'amber' | 'blue' | 'gray' = 'gray'): void {
    // badge-ish filled label; measured for width
    const size = 8.5;
    const w = textWidth(text.toUpperCase(), size, true) + 12;
    this.ensureSpace(18);
    const grayMap = { dark: 0.15, red: 0.55, amber: 0.7, blue: 0.45, gray: 0.88 };
    this.ops.push({ x: MARGIN, y: this.cursorY - 12, w, h: 13, gray: grayMap[color] });
    this.ops.push({ x: MARGIN + 6, y: this.cursorY - 9, size, bold: true, text: text.toUpperCase() });
    this.cursorY -= 20;
  }

  space(dy: number): void {
    this.cursorY -= dy;
  }

  /** Build the final PDF file bytes. Adds page numbers as a last step. */
  finish(title: string): Uint8Array {
    this.newPage();

    // page objects + content
    const objects: string[] = []; // 1-indexed body strings
    const pageObjNums: number[] = [];
    const contentStart = 5; // 1 catalog, 2 pages, 3 F1, 4 F2 → pages from 5
    const pageNumbers: string[] = [];

    this.pages.forEach((ops, idx) => {
      const pageNum = idx + 1;
      const contentNum = contentStart + this.pages.length + idx * 1; // contents after all page objs
      const pageObj = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W.toFixed(2)} ${PAGE_H.toFixed(2)}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentNum} 0 R >>`;
      pageObjNums.push(contentStart + idx);
      pageNumbers.push(pageObj);

      const parts: string[] = [];
      for (const op of ops) {
        if ('text' in op) {
          parts.push(`BT 0 g /${op.bold ? 'F2' : 'F1'} ${op.size} Tf 1 0 0 1 ${op.x.toFixed(2)} ${op.y.toFixed(2)} Tm (${pdfEscape(op.text)}) Tj ET`);
        } else if ('x1' in op) {
          parts.push(`${op.gray} G ${op.width} w ${op.x1.toFixed(2)} ${op.y1.toFixed(2)} m ${op.x2.toFixed(2)} ${op.y2.toFixed(2)} l S`);
        } else {
          parts.push(`${op.gray} g ${op.x.toFixed(2)} ${op.y.toFixed(2)} ${op.w.toFixed(2)} ${op.h.toFixed(2)} re f`);
        }
      }
      // footer page number
      parts.push(`BT /F1 8 Tf 1 0 0 1 ${(PAGE_W / 2 - 20).toFixed(2)} 30 Tm (${pdfEscape(`Page ${pageNum} / ${this.pages.length} — ${title}`)}) Tj ET`);

      const content = parts.join('\n');
      objects[contentNum] = `<< /Length ${Buffer.byteLength(content, 'latin1')} >>\nstream\n${content}\nendstream`;
      pageNumbers[pageNum - 1] = pageObj; // reuse array slot for page object string
    });

    // assemble body: [1]=catalog [2]=pages [3]=F1 [4]=F2 [5..5+P-1]=pages [5+P..5+2P-1]=contents
    const total = 4 + this.pages.length * 2;
    const body: string[] = new Array(total + 1).fill('');
    body[1] = '<< /Type /Catalog /Pages 2 0 R >>';
    body[2] = `<< /Type /Pages /Kids [${pageObjNums.map((n) => `${n} 0 R`).join(' ')}] /Count ${this.pages.length} >>`;
    body[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';
    body[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>';
    this.pages.forEach((_, idx) => {
      const pageObjNum = 5 + idx;
      body[pageObjNum] = pageNumbers[idx]!;
      const contentNum = 5 + this.pages.length + idx;
      // content strings were stored at their object numbers inside objects[] above
      body[contentNum] = objects[contentNum]!;
    });

    let out = '%PDF-1.4\n';
    const offsets: number[] = [];
    for (let i = 1; i <= total; i++) {
      offsets[i] = Buffer.byteLength(out, 'latin1');
      out += `${i} 0 obj\n${body[i]}\nendobj\n`;
    }
    const xrefStart = Buffer.byteLength(out, 'latin1');
    out += `xref\n0 ${total + 1}\n0000000000 65535 f \n`;
    for (let i = 1; i <= total; i++) {
      out += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
    }
    out += `trailer\n<< /Size ${total + 1} /Root 1 0 R /Info << /Title (${pdfEscape(title)}) /Producer (owasp-assessment-platform) >> >>\nstartxref\n${xrefStart}\n%%EOF\n`;
    return new Uint8Array(Buffer.from(out, 'latin1'));
  }
}
