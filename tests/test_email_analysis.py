# tests/test_email_analysis.py
# Python port of the analyzer test suite: exercises the same analysers on the
# same fixtures as tests/analyzer.test.js, plus end-to-end .eml file parsing.
import os
import unittest

import email_analysis as e


H = {'name': None, 'value': None, 'raw': None}


def make_message(headers):
    return '\r\n'.join(headers) + '\r\n\r\nThis is the body.\r\n'


def pipeline(raw):
    r = e.analyze_raw(raw)
    return {
        'auth': r['capsules']['auth'],
        'routing': r['capsules']['routing'],
        'sender': r['capsules']['sender'],
        'warnings': r['warnings'],
        'authentication': r['authentication'],
        'report': r,
    }


def indicator_ids(indicators):
    return [i.get('id') for i in (indicators or []) if i.get('id')]


FIX_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def load_fixture(name):
    with open(os.path.join(FIX_DIR, name), 'rb') as f:
        return f.read().decode('utf-8', 'replace')


FIXTURES = {
    # SPF/DKIM/DMARC all-pass message as seen by Gmail.
    'authPass': [
        'Return-Path: <noreply@example.com>',
        'Received: from mail.example.com (mail.example.com [192.0.2.10])',
        '  by mail.google.com with ESMTPS id ABC123;',
        '  Fri, 02 Jan 2026 08:00:00 +0000',
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@example.com header.s=selector1 header.b=xyz;',
        '       spf=pass smtp.mailfrom=noreply@example.com;',
        '       dmarc=pass (p=REJECT sp=REJECT) header.from=noreply@example.com',
        'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;',
        ' s=selector1; h=from:to:subject; bh=abc; b=xyz',
        'From: "Example Mail" <noreply@example.com>',
        'To: user@gmail.com',
        'Subject: SPF/DKIM/DMARC pass test',
        'Date: Fri, 02 Jan 2026 08:00:00 +0000',
        'Message-ID: <12345@example.com>',
        'Reply-To: support@example.com',
        'User-Agent: Mozilla/5.0 (X11; Linux) Thunderbird/128.0',
        '',
    ],
    'authFail': [
        'Return-Path: <bounce@evil-attacker.net>',
        'Received: from pwn.example.net (pwn.example.net [203.0.113.9])',
        '  by mail.google.com with ESMTPS id ZZZ999; Fri, 02 Jan 2026 09:00:00 +0000',
        'Authentication-Results: mx.google.com;',
        '       spf=fail smtp.mailfrom=evil-attacker.net;',
        '       dkim=fail header.d=evil-attacker.net header.s=badsig;',
        '       dmarc=fail (p=NONE) header.from=evil-attacker.net',
        'From: "Your Bank" <no-reply@bank-legit.example>',
        'To: victim@gmail.com',
        'Subject: SPF/DKIM/DMARC fail test',
        'Message-ID: <666@evil-attacker.net>',
        '',
    ],
    'multiAuthResults': [
        'Received: from a.example.net (a.example.net [198.51.100.50])',
        '  by mail.google.com with ESMTPS id Q1; Fri, 02 Jan 2026 10:00:00 +0000',
        'Authentication-Results: mx.google.com;',
        '       spf=pass smtp.mailfrom=legit.example;',
        '       dmarc=pass header.from=legit.example',
        'Authentication-Results: lists.example.org;',
        '       dkim=pass header.d=lists.example.org',
        'From: Newsletter <news@legit.example>',
        'To: user@gmail.com',
        'Subject: multiple A-R headers',
        '',
    ],
    'routeExample': [
        'Received: from mx2.example.net',
        '          (mx2.example.net [198.51.100.30])',
        '          by gmail.com with ESMTPS id C;',
        '          Fri, 02 Jan 2026 08:00:02 +0000',
        'Received: from mx1.example.net',
        '          ([198.51.100.20])',
        '          by mx2.example.net with ESMTPS id B;',
        '          Fri, 02 Jan 2026 08:00:01 +0000 (UTC)',
        'Received: from sender.example.com',
        '          (sender.example.com [192.0.2.10])',
        '          by mx1.example.net with ESMTP id A;',
        '          Fri, 02 Jan 2026 08:00:00 +0000',
        'From: Sender <sender@example.com>',
        'To: user@gmail.com',
        'Subject: routing example',
        '',
    ],
    'privateSource': [
        'Received: from internal.example (internal.example [192.168.1.5])',
        '  by mail.google.com with ESMTP id P; Fri, 02 Jan 2026 11:00:00 +0000',
        'Authentication-Results: mx.google.com;',
        '       spf=pass smtp.mailfrom=internal.example',
        'From: Internal <it@internal.example>',
        'To: user@gmail.com',
        'Subject: private IP test',
        '',
    ],
    'ipv6Source': [
        'Received: from mail6.example.net ([IPv6:2001:db8::1])',
        '  by mail.google.com with ESMTPS id V6; Fri, 02 Jan 2026 12:00:00 +0000',
        'From: Six <v6@example.net>',
        'To: user@gmail.com',
        'Subject: ipv6 test',
        '',
    ],
    'malformedReceived': [
        'Received: this is not a recognized Received format ((((unbalanced',
        'From: Odd <odd@example.net>',
        'To: user@gmail.com',
        'Subject: malformed received',
        '',
    ],
    'mismatchFromReplyTo': [
        'From: support@example.com',
        'Reply-To: attacker@example.net',
        'Return-Path: <bounce@example.org>',
        'To: user@gmail.com',
        'Subject: mismatch reply-to',
        'User-Agent: Outlook Express',
        '',
    ],
    'noReplyToNoReturnPath': [
        'From: plain@example.com',
        'To: user@gmail.com',
        'Subject: missing headers',
        'Message-ID: <m@example.com>',
        '',
    ],
    'encodedValues': [
        'From: "=?UTF-8?Q?Doe=2C_John?=" <john@example.com>',
        'Reply-To: "Boss, The" <boss@example.net>',
        'Return-Path: <MAILER-DAEMON@>',
        'To: "Undisclosed; :;" <undisclosed-recipient:;>',
        'Subject: =?UTF-8?B?SGVsbG8gV29ybGQ=?=',
        'Message-ID: <quoted@example.com>',
        '',
    ],
}


def build(name):
    return make_message(FIXTURES[name])


class TestAuthentication(unittest.TestCase):
    def test_spf_pass(self):
        auth = pipeline(build('authPass'))['auth']
        self.assertEqual(auth['spf']['result'], 'pass')
        self.assertEqual(auth['spf']['status'], 'pass')
        self.assertEqual(auth['spf']['domain'], 'example.com')
        self.assertEqual(auth['spf']['clientIp'], '192.0.2.10')

    def test_spf_fail(self):
        auth = pipeline(build('authFail'))['auth']
        self.assertEqual(auth['spf']['result'], 'fail')
        self.assertEqual(auth['spf']['status'], 'fail')
        self.assertEqual(auth['spf']['domain'], 'evil-attacker.net')
        self.assertIn('spf-failure', indicator_ids(auth['indicators']))

    def test_dkim_pass(self):
        auth = pipeline(build('authPass'))['auth']
        self.assertEqual(auth['dkim']['result'], 'pass')
        self.assertEqual(auth['dkim']['domain'], 'example.com')
        self.assertEqual(auth['dkim']['selector'], 'selector1')
        self.assertEqual(auth['dkim']['algorithm'], 'rsa-sha256')
        self.assertEqual(auth['dkim']['canonicalization'], 'relaxed/relaxed')

    def test_dkim_fail(self):
        auth = pipeline(build('authFail'))['auth']
        self.assertEqual(auth['dkim']['result'], 'fail')
        self.assertEqual(auth['dkim']['status'], 'fail')
        self.assertIn('dkim-failure', indicator_ids(auth['indicators']))

    def test_dmarc_pass(self):
        auth = pipeline(build('authPass'))['auth']
        self.assertEqual(auth['dmarc']['result'], 'pass')
        self.assertEqual(auth['dmarc']['policy'], 'reject')
        self.assertEqual(auth['dmarc']['domain'], 'example.com')
        self.assertEqual(auth['dmarc']['spfAlignment'], 'pass')
        self.assertEqual(auth['dmarc']['dkimAlignment'], 'pass')

    def test_dmarc_fail(self):
        auth = pipeline(build('authFail'))['auth']
        self.assertEqual(auth['dmarc']['result'], 'fail')
        self.assertEqual(auth['dmarc']['status'], 'fail')
        self.assertIn('dmarc-failure', indicator_ids(auth['indicators']))

    def test_multiple_auth_results_preserved(self):
        auth = pipeline(build('multiAuthResults'))['auth']
        self.assertEqual(len(auth['declarations']), 2)
        self.assertEqual([d['authservId'] for d in auth['declarations']],
                         ['mx.google.com', 'lists.example.org'])
        self.assertEqual(auth['primaryAuthservId'], 'mx.google.com')
        self.assertIn('multiple-auth-results', indicator_ids(auth['indicators']))

    def test_missing_auth_results(self):
        raw = '\r\n'.join(['From: a@b.c', 'To: d@e.f', 'Subject: x', '']) + '\r\n\r\n'
        auth = pipeline(raw)['auth']
        self.assertEqual(auth['spf']['result'], 'not_available')
        self.assertIn('missing-auth-results', indicator_ids(auth['indicators']))


class TestRouting(unittest.TestCase):
    def test_route_example(self):
        routing = pipeline(build('routeExample'))['routing']
        self.assertEqual(routing['hopCount'], 3)
        self.assertEqual(routing['source']['ip'], '192.0.2.10')
        self.assertEqual(routing['source']['host'], 'sender.example.com')
        self.assertEqual(routing['source']['confidence'], 'high')
        self.assertEqual(len(routing['intermediates']), 2)
        self.assertEqual(routing['intermediates'][0]['host'], 'mx1.example.net')
        self.assertEqual(routing['intermediates'][1]['host'], 'mx2.example.net')
        self.assertEqual(routing['destination']['host'], 'gmail.com')
        self.assertEqual([n['role'] for n in routing['nodes']],
                         ['source', 'mta', 'mta', 'destination'])
        self.assertEqual(routing['nodes'][3]['host'], 'gmail.com')

    def test_ipv4_source(self):
        routing = pipeline(build('routeExample'))['routing']
        self.assertEqual(routing['source']['ip'], '192.0.2.10')
        self.assertEqual(routing['source']['ipType'], 'ipv4')

    def test_ipv6_source(self):
        routing = pipeline(build('ipv6Source'))['routing']
        self.assertEqual(routing['source']['ip'], '2001:db8::1')

    def test_folded_received_parse(self):
        routing = pipeline(build('routeExample'))['routing']
        self.assertEqual(routing['hopCount'], 3)
        self.assertEqual(routing['parseErrors'], 0)

    def test_private_source_flagged(self):
        routing = pipeline(build('privateSource'))['routing']
        self.assertEqual(routing['source']['ip'], '192.168.1.5')
        self.assertTrue(routing['source']['privateInfo']['isPrivate'])
        self.assertIn('private-source-ip', indicator_ids(routing['indicators']))

    def test_malformed_received_flagged(self):
        routing = pipeline(build('malformedReceived'))['routing']
        self.assertEqual(routing['source']['confidence'], 'unknown')
        self.assertTrue(routing['source']['reason'])
        self.assertIn('malformed-received', indicator_ids(routing['indicators']))

    def test_unknown_source_no_guess(self):
        raw = '\r\n'.join(['From: x@example.com', 'To: y@example.com', 'Subject: z',
                           'Message-ID: <1@x>', '']) + '\r\n\r\n'
        routing = pipeline(raw)['routing']
        self.assertIsNone(routing['source']['ip'])
        self.assertFalse(routing['source']['determined'])


class TestSender(unittest.TestCase):
    def test_missing_reply_to(self):
        sender = pipeline(build('noReplyToNoReturnPath'))['sender']
        self.assertIsNone(sender['replyTo'])

    def test_missing_return_path(self):
        sender = pipeline(build('noReplyToNoReturnPath'))['sender']
        self.assertIsNone(sender['returnPath'])
        self.assertIsNone(sender['returnPathRaw'])

    def test_from_reply_to_mismatch(self):
        sender = pipeline(build('mismatchFromReplyTo'))['sender']
        self.assertEqual(sender['from']['email'], 'support@example.com')
        self.assertEqual(sender['replyTo']['email'], 'attacker@example.net')
        self.assertIn('from-replyto-mismatch', indicator_ids(sender['indicators']))
        self.assertTrue(any(d['kind'] == 'from-replyto' for d in sender['differences']))

    def test_from_return_path_mismatch(self):
        sender = pipeline(build('mismatchFromReplyTo'))['sender']
        self.assertEqual(sender['returnPath']['email'], 'bounce@example.org')
        self.assertIn('from-returnpath-mismatch', indicator_ids(sender['indicators']))
        self.assertTrue(any(d['kind'] == 'from-returnpath' for d in sender['differences']))

    def test_missing_user_agent(self):
        sender = pipeline(build('noReplyToNoReturnPath'))['sender']
        self.assertIsNone(sender['userAgent'])
        self.assertIn('missing-user-agent', indicator_ids(sender['indicators']))

    def test_user_agent_surfaced(self):
        sender = pipeline(build('authPass'))['sender']
        self.assertTrue(sender['userAgent'] and 'Thunderbird' in sender['userAgent'])
        self.assertNotIn('missing-user-agent', indicator_ids(sender['indicators']))

    def test_quoted_encoded_values(self):
        sender = pipeline(build('encodedValues'))['sender']
        self.assertEqual(sender['from']['displayName'], 'Doe, John')
        self.assertEqual(sender['from']['email'], 'john@example.com')
        self.assertEqual(sender['replyTo']['displayName'], 'Boss, The')

    def test_no_mismatch_same_addresses(self):
        raw = '\r\n'.join([
            'From: Site <noreply@example.com>',
            'Reply-To: "Site" <noreply@example.com>',
            'Return-Path: <noreply@example.com>',
            'To: user@gmail.com',
            'User-Agent: Mailer',
            '',
        ]) + '\r\n\r\n'
        sender = pipeline(raw)['sender']
        self.assertNotIn('from-replyto-mismatch', indicator_ids(sender['indicators']))
        self.assertNotIn('from-returnpath-mismatch', indicator_ids(sender['indicators']))


class TestLowLevel(unittest.TestCase):
    def test_address_group_syntax(self):
        # Obsolete group syntax is handled the same way as the JS original.
        lst = e.parse_address_list('Friends: jane@example.org;')
        self.assertEqual(len(lst['addresses']), 1)
        self.assertEqual(lst['addresses'][0]['email'], 'jane@example.org')

    def test_same_address_case_insensitive(self):
        a = e.parse_address('John <John@Example.COM>')
        b = e.parse_address('<john@example.com>')
        self.assertTrue(e.same_address(a, b))

    def test_bare_address_display_empty(self):
        a = e.parse_address('billing@example.com')
        self.assertEqual(a['email'], 'billing@example.com')
        self.assertIsNone(a['displayName'])

    def test_ipv6_bracket_literal_extraction(self):
        ips = e.extract_ips('from ([IPv6:2001:db8::1]) by mail.example.net')
        self.assertTrue(any(x['type'] == 'ipv6' and x['ip'] == '2001:db8::1' for x in ips))

    def test_documentation_ranges_not_private(self):
        self.assertFalse(e.private_ip_info('192.0.2.10')['isPrivate'])
        self.assertFalse(e.private_ip_info('198.51.100.77')['isPrivate'])
        self.assertFalse(e.private_ip_info('203.0.113.9')['isPrivate'])
        self.assertTrue(e.private_ip_info('192.168.1.5')['isPrivate'])

    def test_registrable_domain_two_level(self):
        self.assertEqual(e.registrable_domain('mail.example.co.uk'), 'example.co.uk')
        self.assertEqual(e.registrable_domain('mx.google.com'), 'google.com')

    def test_split_top_level_respects_parens(self):
        parts = e.split_top_level('spf=pass (a comment with ; semicolon); dmarc=pass')
        self.assertEqual(len(parts), 2)
        self.assertIn('dmarc=pass', parts[1])

    def test_analysis_text_export(self):
        txt = e.analysis_text(pipeline(build('authPass'))['report'])
        self.assertIn('SPF', txt)
        self.assertIn('Source IP', txt)


class TestEmlFiles(unittest.TestCase):
    # Each fixture requires newline bytes; load and analyze as a real .eml file.
    def test_full_eml(self):
        report = e.analyze_raw(load_fixture('full.eml'), 'full.eml')
        auth = report['capsules']['auth']
        self.assertEqual(auth['spf']['result'], 'pass')
        self.assertEqual(auth['dkim']['result'], 'pass')
        self.assertEqual(auth['dmarc']['result'], 'pass')
        self.assertEqual(report['routing']['sourceIp'], '192.0.2.10')
        self.assertEqual(report['routing']['confidence'], 'high')
        self.assertEqual(report['routing']['hopCount'], 2)
        self.assertEqual(report['sender']['subject'], 'Invoice #88213 -- payment reminder')
        self.assertIn('Received: from mail-relay-1', report['rawHeaders'])
        self.assertEqual(report['meta']['source'], 'eml-file')
        self.assertGreater(len(e.analysis_text(report)), 100)

    def test_ipv6_eml_one_hop(self):
        report = e.analyze_raw(load_fixture('ipv6.eml'), 'ipv6.eml')
        self.assertEqual(report['routing']['sourceIp'], '2001:db8::1234')
        self.assertEqual(report['routing']['hopCount'], 1)
        self.assertIn('single-hop', indicator_ids(report['warnings']))
        self.assertEqual(report['sender']['from']['displayName'], 'Nadia Hassan')

    def test_spoofy_eml(self):
        report = e.analyze_raw(load_fixture('spoofy.eml'), 'spoofy.eml')
        self.assertEqual(report['sender']['from']['email'],
                         'account@secure-update.paypalbuy-verify.example')
        self.assertEqual(report['sender']['from']['displayName'],
                         'PayPal, Your account is suspended')
        self.assertEqual(report['sender']['replyTo']['email'],
                         'verify@paypal-accounts-alert.example')
        ids = indicator_ids(report['warnings'])
        self.assertIn('from-replyto-mismatch', ids)
        self.assertIn('obfuscated-display', ids)
        self.assertIn('missing-auth-results', ids)
        self.assertIn('missing-user-agent', ids)


class TestContent(unittest.TestCase):
    def _attachment_eml(self):
        return '\r\n'.join([
            'From: a@b.com',
            'To: c@d.com',
            'Subject: attachment test',
            'Content-Type: multipart/mixed; boundary="ZZBOUND"',
            '',
            '--ZZBOUND',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 7bit',
            '',
            'Please see the attached file and visit https://example.com/invoice.',
            '--ZZBOUND',
            'Content-Type: application/pdf; name="invoice.pdf"',
            'Content-Disposition: attachment; filename="invoice.pdf"',
            'Content-Transfer-Encoding: base64',
            '',
            'JVBERi0xLjQKJf////8=',
            '--ZZBOUND--',
        ]) + '\r\n'

    def test_attachment_extracted_with_payload(self):
        import base64 as b64
        report = e.analyze_raw(self._attachment_eml(), 'att.eml')
        content = report['content']
        self.assertEqual(len(content['attachments']), 1)
        att = content['attachments'][0]
        self.assertEqual(att['filename'], 'invoice.pdf')
        self.assertEqual(att['mediaType'], 'application/pdf')
        self.assertEqual(att['disposition'], 'attachment')
        self.assertFalse(att['inline'])
        self.assertTrue(att['hasData'])
        payload = b64.b64decode(att['base64'])
        self.assertEqual(att['size'], len(payload))
        self.assertTrue(payload.startswith(b'%PDF-1.4'))

    def test_plain_parts_not_attachments(self):
        report = e.analyze_raw(self._attachment_eml(), 'att.eml')
        content = report['content']
        self.assertEqual(len(content['attachments']), 1, 'only the named part is an attachment')
        self.assertIn('Please see the attached file', content['plainText'])

    def test_links_extracted_from_decoded_body(self):
        report = e.analyze_raw(self._attachment_eml(), 'att.eml')
        links = report['content']['links']
        self.assertIn('https://example.com/invoice', links)

    def test_no_content_without_body(self):
        raw = '\r\n'.join(['From: a@b.com', 'To: c@d.com', 'Subject: x', '']) + '\r\n\r\n'
        report = e.analyze_raw(raw)
        self.assertEqual(report['content']['attachments'], [])
        self.assertEqual(report['content']['links'], [])

    def test_analysis_text_includes_attachments_and_links(self):
        report = e.analyze_raw(self._attachment_eml(), 'att.eml')
        txt = e.analysis_text(report)
        self.assertIn('Attachments (1)', txt)
        self.assertIn('invoice.pdf', txt)
        self.assertIn('Links (1)', txt)
        self.assertIn('https://example.com/invoice', txt)

    def test_full_eml_content_key_present(self):
        report = e.analyze_raw(load_fixture('full.eml'), 'full.eml')
        self.assertIn('content', report)
        self.assertIsInstance(report['content']['attachments'], list)


if __name__ == '__main__':
    unittest.main()