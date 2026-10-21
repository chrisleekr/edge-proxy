import { json } from '@codemirror/lang-json';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags } from '@lezer/highlight';
import { basicSetup, EditorView } from 'codemirror';
import { useEffect, useRef } from 'react';

// theme maps CodeMirror's default light look onto the design tokens. Long
// documents scroll inside the editor so the page keeps its other controls
// in reach.
const theme = EditorView.theme({
  '&': { backgroundColor: 'var(--color-panel)', color: 'var(--color-heading)', fontSize: '0.875rem', maxHeight: '32rem' },
  '&.cm-focused': { outline: 'none' },
  '.cm-scroller': { fontFamily: 'var(--font-mono)' },
  '.cm-content': { caretColor: 'var(--color-brand)' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--color-brand)' },
  '.cm-gutters': { backgroundColor: 'var(--color-soft)', color: 'var(--color-body)', borderRight: '1px solid var(--color-line)' },
  '.cm-activeLine': { backgroundColor: 'var(--color-soft)' },
  '.cm-activeLineGutter': { backgroundColor: 'var(--color-line)', color: 'var(--color-heading)' },
  '&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection': {
    backgroundColor: 'var(--color-line)',
  },
  '.cm-selectionMatch': { backgroundColor: 'var(--color-line)', outline: '1px solid var(--color-line)' },
  '&.cm-focused .cm-matchingBracket': { backgroundColor: 'var(--color-line)', outline: '1px solid var(--color-body)' },
  '&.cm-focused .cm-nonmatchingBracket': { backgroundColor: 'transparent', outline: '1px solid var(--color-danger)' },
  '.cm-foldPlaceholder': { backgroundColor: 'var(--color-soft)', border: '1px solid var(--color-line)', color: 'var(--color-body)' },
  '.cm-tooltip': { backgroundColor: 'var(--color-panel)', border: '1px solid var(--color-line)', borderRadius: 'var(--radius-control)' },
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': { backgroundColor: 'var(--color-brand)', color: 'var(--color-on-brand)' },
  '.cm-panels': { backgroundColor: 'var(--color-soft)', color: 'var(--color-heading)' },
  '.cm-panels.cm-panels-bottom': { borderTop: '1px solid var(--color-line)' },
  '.cm-button': { backgroundImage: 'none', backgroundColor: 'var(--color-panel)', border: '1px solid var(--color-line)', borderRadius: 'var(--radius-tab)' },
  '.cm-searchMatch': { backgroundColor: 'transparent', outline: '1px solid var(--color-warning)' },
  '.cm-searchMatch.cm-searchMatch-selected': { backgroundColor: 'var(--color-line)' },
});

// highlight is monochrome: the default palette paints strings red, which
// reads as an error here. Keys lead and values sit back.
const highlight = HighlightStyle.define([
  { tag: tags.propertyName, color: 'var(--color-heading)', fontWeight: '500' },
  { tag: tags.string, color: 'var(--color-body)' },
  { tag: [tags.number, tags.bool, tags.null], color: 'var(--color-heading)', fontStyle: 'italic' },
  { tag: [tags.punctuation, tags.separator, tags.squareBracket, tags.brace], color: 'var(--color-body)' },
  { tag: tags.invalid, color: 'var(--color-danger)', textDecoration: 'underline wavy' },
]);

// CodeEditor is CodeMirror 6, kept in sync with value when it changes from
// outside (for example after a reload). ui.tsx loads it on first use.
export default function CodeEditor({ value, onChange, label, language }: { value: string; onChange: (v: string) => void; label: string; language?: 'json' }) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView>(null);
  const changed = useRef(onChange);
  useEffect(() => {
    changed.current = onChange;
  });
  // Text set from value is not an edit: reporting it would turn a refetched
  // draft into an unsaved change.
  const outside = useRef(false);
  useEffect(() => {
    view.current = new EditorView({
      parent: host.current!,
      doc: value,
      extensions: [
        basicSetup,
        theme,
        syntaxHighlighting(highlight),
        ...(language === 'json' ? [json()] : []),
        EditorView.lineWrapping,
        EditorView.contentAttributes.of({ 'aria-label': label }),
        EditorView.updateListener.of((u) => u.docChanged && !outside.current && changed.current(u.state.doc.toString())),
      ],
    });
    return () => view.current?.destroy();
    // The editor is created once; value changes are applied below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    const v = view.current;
    if (!v || v.state.doc.toString() === value) return;
    outside.current = true;
    v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value } });
    outside.current = false;
  }, [value]);
  return <div ref={host} className="overflow-hidden rounded-control bg-panel shadow-field focus-within:outline-2 focus-within:outline-focus" />;
}
