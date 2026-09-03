class StrictJsonParser {
  constructor(text) {
    this.text = text;
    this.position = 0;
  }

  parse() {
    this.value();
    this.space();
    if (this.position !== this.text.length) throw new Error('trailing JSON input');
  }

  space() {
    while ([' ', '\t', '\n', '\r'].includes(this.text[this.position])) this.position += 1;
  }

  value() {
    this.space();
    const token = this.text[this.position];
    if (token === '{') return this.object();
    if (token === '[') return this.array();
    if (token === '"') return this.string();
    if (token === 't') return this.literal('true');
    if (token === 'f') return this.literal('false');
    if (token === 'n') return this.literal('null');
    return this.number();
  }

  object() {
    const keys = new Set();
    this.position += 1;
    this.space();
    if (this.text[this.position] === '}') { this.position += 1; return; }
    while (true) {
      this.space();
      if (this.text[this.position] !== '"') throw new Error('object key is not a string');
      const key = this.string();
      if (keys.has(key)) throw new Error(`duplicate JSON property: ${key}`);
      keys.add(key);
      this.space();
      if (this.text[this.position] !== ':') throw new Error('missing object colon');
      this.position += 1;
      this.value();
      this.space();
      const delimiter = this.text[this.position++];
      if (delimiter === '}') return;
      if (delimiter !== ',') throw new Error('invalid object delimiter');
    }
  }

  array() {
    this.position += 1;
    this.space();
    if (this.text[this.position] === ']') { this.position += 1; return; }
    while (true) {
      this.value();
      this.space();
      const delimiter = this.text[this.position++];
      if (delimiter === ']') return;
      if (delimiter !== ',') throw new Error('invalid array delimiter');
    }
  }

  string() {
    const start = this.position;
    this.position += 1;
    let escaped = false;
    while (this.position < this.text.length) {
      const character = this.text[this.position++];
      if (!escaped && character === '"') {
        return JSON.parse(this.text.slice(start, this.position));
      }
      if (!escaped && character === '\\') escaped = true;
      else escaped = false;
    }
    throw new Error('unterminated JSON string');
  }

  literal(token) {
    if (this.text.slice(this.position, this.position + token.length) !== token) {
      throw new Error('invalid JSON literal');
    }
    this.position += token.length;
  }

  number() {
    const match = this.text.slice(this.position).match(
      /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/,
    );
    if (!match || !Number.isFinite(Number(match[0]))) throw new Error('invalid JSON number');
    this.position += match[0].length;
  }
}

export function parseStrictJson(text) {
  if (typeof text !== 'string') throw new Error('JSON input is not text');
  new StrictJsonParser(text).parse();
  return JSON.parse(text);
}
