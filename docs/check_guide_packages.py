"""Validate generated Office packages and bilingual content without Word."""
from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET
import re

root = Path(__file__).resolve().parent
ns = {'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
for name, expected_chapters in [('HoneyTrace_Technical_Guide_EN_MY.docx',20),
                                 ('HoneyTrace_Presentation_Guide_EN_MY.docx',12)]:
    with ZipFile(root/name) as archive:
        assert archive.testzip() is None
        for part in archive.namelist():
            if part.endswith(('.xml','.rels')): ET.fromstring(archive.read(part))
        doc = ET.fromstring(archive.read('word/document.xml'))
        text = '\n'.join(node.text or '' for node in doc.findall('.//w:t',ns))
        assert '\ufffd' not in text and 'TODO' not in text
        assert len(re.findall('[\u1000-\u109f]',text)) > 15000
        body = doc.find('w:body',ns)
        headings=[]
        en_count=my_count=0
        for paragraph in body.findall('w:p',ns):
            style = paragraph.find('w:pPr/w:pStyle',ns)
            content=''.join(x.text or '' for x in paragraph.findall('.//w:t',ns))
            if style is not None and style.get('{'+ns['w']+'}val')=='Heading1': headings.append(content)
            if content=='ENGLISH': en_count+=1
            if content=='မြန်မာ': my_count+=1
        assert headings[0].startswith('Reading map')
        assert len(headings)==expected_chapters+1, headings
        assert en_count==my_count and en_count>20
        assert text.index('Reading map') < text.index('1. ')
        print(name, {'chapters':expected_chapters,'paired_passages':en_count,
              'tables':len(doc.findall('.//w:tbl',ns)),
              'Myanmar_characters':len(re.findall('[\u1000-\u109f]',text)),
              'English_tokens':len(re.findall(r'[A-Za-z]+(?:[-_][A-Za-z]+)*',text)),
              'validation':'PASS'})
