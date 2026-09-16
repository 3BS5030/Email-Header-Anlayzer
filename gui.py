# gui.py
# Tkinter desktop interface for the Email Header Analyzer (email_analysis.py).
# Stdlib only. Run through main.py:  python main.py [path-to-.eml]
import base64
import json
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import email_analysis


# --------------------------------------------------------------------------- palette
BG          = '#f1f3f4'   # page background
CARD_BG     = '#ffffff'   # card / panel background
BORDER      = '#dadce0'   # card border
ACCENT      = '#1a73e8'   # primary blue
ACCENT_DK   = '#174ea6'
TEXT        = '#202124'
SUB          = '#5f6368'
FAINT       = '#9aa0a6'

STATUS_COLORS = {'pass': '#1e8e3e', 'fail': '#d93025', 'warning': '#e37400',
                 'unknown': '#5f6368', 'na': '#5f6368'}
SEVERITY_COLORS = {'warning': '#e37400', 'info': '#1a73e8'}

ARROW = '\u2193'
FONT = 'Segoe UI'
MONO = 'Consolas'


def _color(stat):
    return STATUS_COLORS.get((stat or '').lower(), '#5f6368')


# ------------------------------------------------------------------ scrollable tab
class ScrollableFrame(ttk.Frame):
    """A vertical-scrollable container (canvas + scrollbar + inner frame)."""

    def __init__(self, master, bg=BG):
        super().__init__(master)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self.vsb = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self.window_id = self.canvas.create_window((0, 0), window=self.inner, anchor='nw')
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side='left', fill='both', expand=True)
        self.vsb.pack(side='right', fill='y')

        self.inner.bind('<Configure>', lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfigure(
            self.window_id, width=e.width))

        self.canvas.bind('<Enter>', self._bind_wheel)
        self.canvas.bind('<Leave>', self._unbind_wheel)
        self.inner.bind('<Enter>', self._bind_wheel)
        self.inner.bind('<Leave>', self._unbind_wheel)

    def _bind_wheel(self, _event=None):
        if self.vsb.get() != (0.0, 1.0):
            self.canvas.bind_all('<MouseWheel>', self._on_wheel)

    def _unbind_wheel(self, _event=None):
        self.canvas.unbind_all('<MouseWheel>')

    def _on_wheel(self, event):
        self.canvas.yview_scroll(-1 if event.delta > 0 else 1, 'units')


# ----------------------------------------------------------------------------- app
class EmailHeaderAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Email Header Analyzer')
        self.geometry('1020x760')
        self.minsize(800, 560)
        self.configure(bg=BG)
        self.report = None
        self.current_path = None
        self.chip_labels = {}

        self._build_style()
        self._build_frame()
        self.bind('<Control-o>', lambda e: self.open_file())
        if not getattr(self, '_headless', False):
            self.center_window()
            self._render_empty()

    # ---------------------------------------------------------------- appearance
    def _build_style(self):
        style = ttk.Style(self)
        if 'vista' in style.theme_names():
            style.theme_use('vista')
        style.configure('Accent.TButton', padding=(18, 7), font=(FONT, 9, 'bold'),
                        background=ACCENT, foreground="#000000")
        style.map('Accent.TButton',
                  background=[('active', ACCENT_DK), ('pressed', '#0d47a1')],
                  foreground=[('disabled', '#8ab4f8')])
        style.configure('TNotebook.Tab', padding=(10, 5), font=(FONT, 9))
        style.configure('TNotebook', background=BG, borderwidth=0)

    # ------------------------------------------------------------------ chrome
    def _build_frame(self):
        # Header
        header = tk.Frame(self, bg=CARD_BG, highlightbackground=BORDER,
                          highlightthickness=1)
        header.pack(fill='x')
        title = tk.Frame(header, bg=CARD_BG)
        title.pack(side='left', padx=14, pady=10)
        tk.Label(title, text='Email Header Analyzer', bg=CARD_BG, fg=TEXT,
                 font=(FONT, 13, 'bold')).pack(anchor='w')
        tk.Label(title, text='SPF  ·  DKIM  ·  DMARC  ·  Mail flow  ·  Identity checks  ·  Attachments & URLs',
                 bg=CARD_BG, fg=SUB, font=(FONT, 8)).pack(anchor='w')
        btns = tk.Frame(header, bg=CARD_BG)
        btns.pack(side='right', padx=14)
        ttk.Button(btns, text='Reload', command=self.reload_current,
                   style='TButton').pack(side='left', padx=(0, 8))
        ttk.Button(btns, text='Open .eml...', command=self.open_file,
                   style='Accent.TButton').pack(side='left')

        # Chips (SPF / DKIM / DMARC / source IP)
        self.chips = tk.Frame(self, bg=BG)
        self.chips.pack(fill='x', padx=12, pady=(10, 0))

        # Subject line
        self.subject_var = tk.StringVar(value='Open an .eml file to begin')
        tk.Label(self, textvariable=self.subject_var, bg=BG, fg=TEXT,
                 font=(FONT, 12, 'bold'), anchor='w').pack(fill='x', padx=14, pady=(6, 0))

        # Confidence banner container (rebuilt on each render)
        self.note_host = tk.Frame(self, bg=BG)
        self.note_host.pack(fill='x', padx=14, pady=(4, 0))

        # Tabs
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill='both', expand=True, padx=12, pady=(8, 8))
        self.tab_auth = self._make_tab('Authentication')
        self.tab_sender = self._make_tab('Sender')
        self.tab_content = self._make_tab('Attachments & URLs')
        self.tab_flow = self._make_tab('Mail Flow')
        self.tab_flags = self._make_tab('Indicators')
        self.tab_raw = ttk.Frame(self.tabs, padding=6)
        self.tabs.add(self.tab_raw, text='Raw Headers')

        # Bottom bar
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill='x', padx=12, pady=(0, 10))
        self.json_btn = ttk.Button(bar, text='Export JSON', command=self.export_json,
                                   state='disabled')
        self.json_btn.pack(side='left')
        self.text_btn = ttk.Button(bar, text='Export Text', command=self.export_text,
                                   state='disabled')
        self.text_btn.pack(side='left', padx=(8, 0))

        # Status bar
        status = tk.Frame(self, bg='#ffffff', highlightbackground=BORDER,
                          highlightthickness=1)
        status.pack(fill='x')
        self.status_left = tk.Label(status, text='ready', bg='#ffffff', fg=SUB,
                                    font=(FONT, 9), anchor='w', padx=12, pady=4)
        self.status_left.pack(side='left')
        self.status_right = tk.Label(status, text='', bg='#ffffff', fg=SUB,
                                     font=(FONT, 9), anchor='e', padx=12, pady=4)
        self.status_right.pack(side='right')

    def _make_tab(self, title):
        frame = ScrollableFrame(self.tabs)
        self.tabs.add(frame, text=title)
        return frame

    def center_window(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry('%dx%d+%d+%d' % (w, h, max(0, (sw - w) // 2), max(0, (sh - h) // 2)))

    # --------------------------------------------------------------------- open
    def open_file(self):
        path = filedialog.askopenfilename(
            title='Choose an email (.eml) file',
            filetypes=[('Email files', '*.eml'), ('All files', '*.*')])
        if path:
            self.load(path)

    def reload_current(self):
        if self.current_path:
            self.load(self.current_path)
        else:
            self.open_file()

    def load(self, path):
        try:
            report = email_analysis.load_and_analyze(path)
        except Exception as exc:  # noqa: BLE001 - surface any parse failure to the user
            messagebox.showerror('Error', 'Could not analyze %s\n\n%s'
                                 % (os.path.basename(path), exc))
            if getattr(self, '_headless', False):
                raise
            return
        self.report = report
        self.current_path = path
        self.json_btn.config(state='normal')
        self.text_btn.config(state='normal')
        self._render(report)

    # ------------------------------------------------------------------- render
    def _render(self, r):
        self._render_chips(r)
        self._render_subject(r)
        self._render_note(r)
        self._render_auth(r)
        self._render_sender(r)
        self._render_content(r)
        self._render_flow(r)
        self._render_indicators(r)
        self._render_raw(r)
        self._render_status(r)

    # ------------------------------------------------------------- cards / rows
    @staticmethod
    def _clear(frame):
        for child in frame.winfo_children():
            child.destroy()

    def _card(self, parent, title=None, accent=ACCENT):
        card = tk.Frame(parent, bg=CARD_BG, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(fill='x', padx=4, pady=(0, 10))
        if title:
            head = tk.Frame(card, bg=CARD_BG)
            head.pack(fill='x', padx=14, pady=(10, 0))
            tk.Label(head, text=title, bg=CARD_BG, fg=accent, anchor='w',
                     font=(FONT, 10, 'bold')).pack(side='left')
            tk.Frame(card, bg='#e8eaed', height=1).pack(fill='x', padx=14, pady=(8, 4))
        return card

    def _row(self, card, label, value, wrap=None, label_width=18):
        row = tk.Frame(card, bg=CARD_BG)
        row.pack(fill='x', padx=14, pady=2)
        tk.Label(row, text=label, width=label_width, anchor='w', bg=CARD_BG,
                 fg=SUB, font=(FONT, 10)).pack(side='left')
        payload = str(value) if value is not None and str(value) != '' else ''
        val = payload or '\u2014'
        tk.Label(row, text=val, anchor='w', justify='left', bg=CARD_BG,
                 fg=TEXT, font=(FONT, 10),
                 wraplength=wrap).pack(side='left', fill='x', expand=True, padx=(8, 6))
        self._copy_button(row, payload).pack(side='right')

    def _copy_button(self, parent, value):
        btn = tk.Button(parent, text='copy', font=(FONT, 8), relief='flat', bd=0,
                        bg=CARD_BG, activebackground='#e8f0fe', fg=ACCENT,
                        activeforeground=ACCENT_DK, cursor='hand2', padx=6)
        payload = value if isinstance(value, str) else str(value or '')

        def do_copy():
            self.clipboard_clear()
            self.clipboard_append(payload)
            btn.config(text='copied', fg='#1e8e3e')
            btn.after(1400, lambda: btn.config(text='copy', fg=ACCENT))

        btn.config(command=do_copy)
        return btn

    def _copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    # -------------------------------------------------------------- chip statuses
    def _render_chips(self, r):
        auth = r['authentication']
        items = [
            ('SPF', auth['spf']['result'], _color(auth['spf']['result'])),
            ('DKIM', auth['dkim']['result'], _color(auth['dkim']['result'])),
            ('DMARC', auth['dmarc']['result'], _color(auth['dmarc']['result'])),
        ]
        src_ip = r['routing']['sourceIp']
        items.append(('SOURCE IP', src_ip or 'unknown', _color('pass') if src_ip else _color('na')))

        for name, value, color in items:
            display = value.upper() if name in ('SPF', 'DKIM', 'DMARC') else value
            text = '%s: %s' % (name, display)
            key = name.lower()
            if key in self.chip_labels:
                lab = self.chip_labels[key]
                lab.config(text=text, background=color, foreground='white')
                lab._chip_payload = text
                continue
            lab = tk.Label(self.chips, text=text, background=color, foreground='white',
                           font=(FONT, 10, 'bold'), padx=9, pady=4, cursor='hand2')
            lab.pack(side='left', padx=(0, 8))
            lab._chip_payload = text
            lab.bind('<Button-1>', lambda e, c=lab: self._copy_chip(c))
            self.chip_labels[key] = lab

    def _copy_chip(self, chip):
        payload = getattr(chip, '_chip_payload', '')
        self._copy_to_clipboard(payload)
        old = chip.cget('text')
        chip.config(text='copied')
        chip.after(1400, lambda: chip.config(text=old))

    # ------------------------------------------------------------- subject / note
    def _render_subject(self, r):
        subj = (r['sender']['subject'] or '').strip()
        self.subject_var.set(('Subject: ' + subj) if subj else '(no subject)')

    def _render_note(self, r):
        self._clear(self.note_host)
        reason = r['routing']['reason']
        if not reason:
            return
        conf = (r['routing']['confidence'] or 'unknown').upper()
        banner = tk.Frame(self.note_host, bg='#e8f0fe', highlightbackground='#aecbfa',
                          highlightthickness=1)
        banner.pack(fill='x')
        tk.Label(banner, text='SOURCE', bg='#e8f0fe', fg=ACCENT_DK,
                 font=(FONT, 8, 'bold')).pack(side='left', padx=(10, 6), pady=6)
        tk.Label(banner, text='confidence: %s  |  %s' % (conf, reason), bg='#e8f0fe',
                 fg='#174ea6', font=(FONT, 9), anchor='w', justify='left',
                 wraplength=840).pack(side='left', fill='x', expand=True, padx=(0, 10))
        self._copy_button(banner, 'confidence: %s | %s' % (conf, reason)).pack(side='right', padx=6)

    # ------------------------------------------------------------------- auth tab
    def _render_auth(self, r):
        auth = r['authentication']
        tab = self.tab_auth.inner
        self._clear(tab)

        spf, dkim, dmarc = auth['spf'], auth['dkim'], auth['dmarc']

        card = self._card(tab, 'SPF', '#c5221f' if spf.get('result') == 'fail' else ACCENT)
        self._row(card, 'Result', spf.get('result'))
        self._row(card, 'Domain', spf.get('domain'))
        self._row(card, 'Client IP', spf.get('clientIp'))
        self._row(card, 'Client IP source', spf.get('clientIpSource'))
        self._row(card, 'Envelope From', spf.get('envelopeFrom'))
        self._row(card, 'HELO', spf.get('helo'))
        self._row(card, 'Scope', spf.get('scope'))

        card = self._card(tab, 'DKIM', '#c5221f' if dkim.get('result') == 'fail' else ACCENT)
        self._row(card, 'Result', dkim.get('result'))
        self._row(card, 'Domain', dkim.get('domain'))
        self._row(card, 'Selector', dkim.get('selector'))
        self._row(card, 'Algorithm', dkim.get('algorithm'))
        self._row(card, 'Canonicalization', dkim.get('canonicalization'))
        self._row(card, 'Signature present', str(dkim.get('signaturePresent')))

        card = self._card(tab, 'DMARC', '#c5221f' if dmarc.get('result') == 'fail' else ACCENT)
        self._row(card, 'Result', dmarc.get('result'))
        self._row(card, 'Domain', dmarc.get('domain'))
        self._row(card, 'Policy', dmarc.get('policy'))
        self._row(card, 'SPF alignment', dmarc.get('spfAlignment'))
        self._row(card, 'DKIM alignment', dmarc.get('dkimAlignment'))

        decs = r['capsules']['auth']['declarations']
        if decs:
            card = self._card(tab, 'Declarations (%d)' % len(decs), SUB)
            for d in decs:
                lines = ['%s: %s' % (x['method'], x['result']) for x in d.get('results', [])]
                self._row(card, d.get('authservId') or '?',
                          '; '.join(lines) if lines else '\u2014', wrap=720)

    # ------------------------------------------------------------------ sender tab
    def _render_sender(self, r):
        s = r['sender']
        tab = self.tab_sender.inner
        self._clear(tab)

        card = self._card(tab, 'Identities')
        self._row(card, 'From', self._addr(s['from']), wrap=640)
        self._row(card, 'Sender', self._addr(s['senderAddr']), wrap=640)
        self._row(card, 'Reply-To', self._addr(s['replyTo']), wrap=640)
        self._row(card, 'Return-Path', self._addr(s['returnPath']), wrap=640)
        self._row(card, 'To', ', '.join(x for x in (self._addr(a) for a in s['to']) if x) or '\u2014',
                  wrap=640)
        self._row(card, 'Cc', ', '.join(x for x in (self._addr(a) for a in s['cc']) if x) or '\u2014',
                  wrap=640)
        self._row(card, 'Date', s['date'])
        self._row(card, 'Message-ID', s['messageId'])
        self._row(card, 'User-Agent', s['userAgent'], wrap=640)

        diffs = r['capsules']['sender']['differences']
        if diffs:
            card = self._card(tab, 'Differences (%d)' % len(diffs), '#e37400')
            for d in diffs:
                self._row(card, d['title'], d['message'], wrap=640, label_width=22)

    # ------------------------------------------------------------- content tab
    def _render_content(self, r):
        content = r.get('content') or {}
        attachments = content.get('attachments') or []
        links = content.get('links') or []
        tab = self.tab_content.inner
        self._clear(tab)

        card = self._card(tab, 'Attachments (%d)' % len(attachments))
        if not attachments:
            tk.Label(card, text='No attachments in this message.', bg=CARD_BG,
                     fg=TEXT, font=(FONT, 10)).pack(padx=14, pady=(6, 12))
        for att in attachments:
            frame = tk.Frame(card, bg=CARD_BG)
            frame.pack(fill='x', padx=14, pady=4)
            name = att.get('filename') or '(unnamed)'
            tk.Label(frame, text=name, anchor='w', justify='left', bg=CARD_BG,
                     fg=TEXT, font=(MONO, 10), wraplength=560).pack(
                side='left', fill='x', expand=True)
            meta = []
            if att.get('mediaType'):
                meta.append(att['mediaType'])
            if att.get('size') is not None:
                meta.append(self._fmt_bytes(att['size']))
            if att.get('disposition'):
                meta.append(att['disposition'])
            if att.get('description'):
                meta.append(att['description'])
            tk.Label(card, text='         ' + '   ·   '.join(meta) or '\u2014',
                     bg=CARD_BG, fg=SUB, font=(FONT, 9), anchor='w',
                     wraplength=760, justify='left').pack(fill='x', padx=(26, 14))
            if att.get('hasData') and att.get('base64'):
                ttk.Button(frame, text='Save as...',
                           command=lambda a=att: self._save_attachment(a),
                           style='TButton').pack(side='right')
            else:
                tk.Label(frame, text='no payload', bg=CARD_BG, fg=FAINT,
                         font=(FONT, 9)).pack(side='right')

        card = self._card(tab, 'URLs (%d)' % len(links))
        if not links:
            tk.Label(card, text='No URLs found in the decoded body.', bg=CARD_BG,
                     fg=TEXT, font=(FONT, 10)).pack(padx=14, pady=(6, 12))
        for url in links:
            frame = tk.Frame(card, bg=CARD_BG)
            frame.pack(fill='x', padx=14, pady=3)
            tk.Label(frame, text=url, anchor='w', justify='left', bg=CARD_BG,
                     fg=TEXT, font=(MONO, 9), wraplength=620).pack(
                side='left', fill='x', expand=True)
            self._copy_button(frame, url).pack(side='right')

    def _save_attachment(self, att):
        if not att or not att.get('base64'):
            return
        default = att.get('filename') or 'attachment.bin'
        path = filedialog.asksaveasfilename(
            title='Save attachment', initialfile=default, defaultextension='.bin',
            filetypes=[('All files', '*.*')])
        if not path:
            return
        try:
            with open(path, 'wb') as f:
                f.write(base64.b64decode(att['base64']))
            messagebox.showinfo('Saved', 'Attachment saved to\n%s' % path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror('Save failed', str(exc))

    @staticmethod
    def _fmt_bytes(n):
        n = int(n or 0)
        if n < 1024:
            return '%d B' % n
        if n < 1048576:
            return '%.1f KB' % (n / 1024)
        return '%.2f MB' % (n / 1048576)

    # ------------------------------------------------------------------- flow tab
    def _render_flow(self, r):
        routing = r['routing']
        tab = self.tab_flow.inner
        self._clear(tab)

        card = self._card(tab, 'Trail  ·  message ID: %s' % (r['meta']['messageId'] or 'unknown'))
        flow = r['mailFlow']
        if not flow:
            self._row(card, 'Flow', 'No Received-chain found.')
        else:
            for i, node in enumerate(flow):
                self._row(card, node['role'].upper(),
                          '%s %s%s' % (node.get('host') or '?',
                                       node.get('ip') or '',
                                       ('  ·  %s' % node['timestamp']) if node.get('timestamp') else ''),
                          wrap=700)
                if i < len(flow) - 1:
                    tk.Label(card, text='      %s' % ARROW, bg=CARD_BG, fg=FAINT,
                             font=(FONT, 9)).pack(anchor='w', padx=14, pady=(0, 1))

        card = self._card(tab, 'Source')
        self._row(card, 'IP', routing['sourceIp'])
        self._row(card, 'Host', routing['sourceHost'])
        self._row(card, 'HELO', routing['sourceHelo'])
        self._row(card, 'Confidence', routing['confidence'])
        self._row(card, 'Reason', routing['reason'], wrap=720)

        card = self._card(tab, 'Destination')
        self._row(card, 'Host', (routing['destination'] or {}).get('host'))
        self._row(card, 'IP', (routing['destination'] or {}).get('ip'))
        self._row(card, 'Hop count', routing['hopCount'])

    # ----------------------------------------------------------------- flags tab
    def _render_indicators(self, r):
        tab = self.tab_flags.inner
        self._clear(tab)
        warnings = r['warnings']
        if not warnings:
            row = self._card(tab)
            tk.Label(row, text='No indicators found.', bg=CARD_BG, fg=TEXT,
                     font=(FONT, 10)).pack(padx=14, pady=10)
            return
        for w in warnings:
            sev = w.get('severity') or 'info'
            color = SEVERITY_COLORS.get(sev, SUB)
            card = self._card(tab)
            head = tk.Frame(card, bg=CARD_BG)
            head.pack(fill='x', padx=14, pady=(10, 0))
            tk.Label(head, text=sev.upper(), bg=CARD_BG, fg=color,
                     font=(FONT, 8, 'bold')).pack(side='left')
            tk.Label(head, text=w['title'], bg=CARD_BG, fg=TEXT,
                     font=(FONT, 10, 'bold')).pack(side='left', padx=(8, 0))
            self._copy_button(head, '%s\n%s' % (w['title'], w['message'])).pack(side='right')
            tk.Label(card, text=w['message'], bg=CARD_BG, fg='#3c4043',
                     font=(FONT, 9), justify='left', anchor='w', wraplength=840,
                     padx=14).pack(fill='x', pady=(2, 10))

    # -------------------------------------------------------------------- raw tab
    def _render_raw(self, r):
        tab = self.tab_raw
        self._clear(tab)
        raw = r['rawHeaders']

        top = tk.Frame(tab, bg=BG)
        top.pack(fill='x')
        ttk.Button(top, text='Copy all headers', command=lambda: self._copy_to_clipboard(raw)
                   ).pack(side='left', pady=(0, 4))

        box = tk.Text(tab, wrap='none', font=(MONO, 9), bg=CARD_BG, fg=TEXT,
                      padx=10, pady=8, selectbackground='#d2e3fc')
        scroll_v = ttk.Scrollbar(tab, orient='vertical', command=box.yview)
        scroll_h = ttk.Scrollbar(tab, orient='horizontal', command=box.xview)
        box.config(yscrollcommand=scroll_v.set, xscrollcommand=scroll_h.set)
        box.insert('1.0', raw or '(no headers captured)')
        scroll_h.pack(side='bottom', fill='x')
        scroll_v.pack(side='right', fill='y')
        box.pack(side='left', fill='both', expand=True)
        box.bind('<MouseWheel>',
                 lambda e: box.yview_scroll(-1 if e.delta > 0 else 1, 'units'))

    # ------------------------------------------------------------------ status bar
    def _render_status(self, r):
        name = os.path.basename(self.current_path or '') or 'no file'
        self.status_left.config(text='file: %s' % name, foreground=SUB)
        n_hop = r['routing']['hopCount']
        n_ind = len(r['warnings'])
        src = r['routing']['sourceIp'] or 'unknown'
        self.status_right.config(
            text='hops: %d      source: %s      indicators: %d' % (n_hop, src, n_ind),
            foreground=SUB)

    # -------------------------------------------------------------------- export
    def _suggest_path(self, suffix):
        if self.current_path:
            return self.current_path.rsplit('.', 1)[0] + suffix
        return suffix.lstrip('.')

    def export_json(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(
            title='Export JSON', defaultextension='.json',
            initialfile=self._suggest_path('-analysis.json'),
            filetypes=[('JSON files', '*.json')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo('Export', 'Saved to\n%s' % path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror('Export failed', str(exc))

    def export_text(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(
            title='Export text report', defaultextension='.txt',
            initialfile=self._suggest_path('-analysis.txt'),
            filetypes=[('Text files', '*.txt')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(email_analysis.analysis_text(self.report))
            messagebox.showinfo('Export', 'Saved to\n%s' % path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror('Export failed', str(exc))

    @staticmethod
    def _addr(a):
        if not a:
            return None
        if a.get('displayName'):
            return '%s <%s>' % (a['displayName'], a['email'])
        return a.get('email')

    # ----------------------------------------------------------------- empty state
    def _render_empty(self):
        tab = self.tab_auth.inner
        card = self._card(tab, 'Welcome')
        tk.Label(card, text='Load a .eml file to analyze its headers.',
                 bg=CARD_BG, fg=TEXT, font=(FONT, 10)).pack(padx=14, pady=(4, 0))
        tk.Label(card,
                 text='The analysis never contacts the network and never marks an '
                      'email as malicious:\nit only reports passive facts (auth results, '
                      'mail-flow trail, identity differences) for you to judge.',
                 bg=CARD_BG, fg=SUB, font=(FONT, 9), justify='left',
                 wraplength=860).pack(padx=14, pady=(0, 10))
        ttk.Button(card, text='Open .eml...', style='Accent.TButton',
                   command=self.open_file).pack(anchor='w', padx=14, pady=(0, 12))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    headless = '--headless' in argv
    app = EmailHeaderAnalyzerApp()
    if headless:
        app._headless = True
        app.withdraw()
    files = [a for a in argv if not a.startswith('-')]
    if files:
        app.load(files[0])
    if headless:
        app.update_idletasks()
        app.destroy()
        print('GUI OK')
        return 0
    app.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())