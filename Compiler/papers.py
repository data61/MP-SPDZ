import re

papers = {
    'ABZS13': 'https://eprint.iacr.org/2012/405',
    'ABY3': 'https://eprint.iacr.org/2018/403',
    'AFLNO16': 'https://eprint.iacr.org/2016/768',
    'AN17': 'https://eprint.iacr.org/2017/816',
    'AS19': 'https://eprint.iacr.org/2019/354',
    'AHIK+22': 'https://eprint.iacr.org/2022/1595',
    'CdH10': 'https://www.researchgate.net/publication/225092133, https://doi.org/10.1007/978-3-642-15317-4_13 (paywall)',
    'CdH10-fixed': 'https://www.ifca.ai/pub/fc10/31_47.pdf',
    'CCD88': 'https://doi.org/10.1145/62212.62214',
    'DDNNT15': 'https://eprint.iacr.org/2015/1006',
    'DEK20': 'https://eprint.iacr.org/2019/131',
    'DEK20-pre': 'https://eprint.iacr.org/archive/2019/131/20191015:083051',
    'EGKRS20': 'https://eprint.iacr.org/2020/338',
    'EKOPPS20': 'https://eprint.iacr.org/2019/164',
    'HICT14': 'https://eprint.iacr.org/2014/121',
    'HIKC23': 'https://doi.org/10.56553/popets-2023-0021',
    'Keller20': 'https://eprint.iacr.org/2020/521',
    'Keller24': 'https://eprint.iacr.org/2024/1990',
    'Keller25': 'https://eprint.iacr.org/2025/919',
    'KOS16': 'https://eprint.iacr.org/2016/505',
    'KPR17': 'https://eprint.iacr.org/2017/1230',
    'KS14': 'https://eprint.iacr.org/2014/137',
    'KSS13': 'https://eprint.iacr.org/2013/143',
    'KS22': 'https://eprint.iacr.org/2022/933',
    'LFHH+20': 'https://doi.org/10.1145/3411501.3419427',
    'NO07': 'https://doi.org/10.1007/978-3-540-71677-8_23',
    'Shi19': 'https://eprint.iacr.org/2019/274',
    'ZWRG+16': 'https://doi.org/10.1109/SP.2016.21',
}

protocol_papers = {
    'astra': 'Keller25',
    'atlas': 'https://eprint.iacr.org/2021/833',
    '-bmr': 'https://eprint.iacr.org/2017/981',
    'brain': 'EKOPPS20',
    '^ccd': ('shamir', 'CCD88'),
    'c.*gear': ('KPR17', 'https://eprint.iacr.org/2019/035'),
    '[^c]*gear': ('cowgear', 'https://eprint.iacr.org/2019/1300'),
    'dealer': 'https://mp-spdz.readthedocs.io/en/latest/readme.html#dealer-model',
    'hemi': ('KS22', 'KPR17', 'https://eprint.iacr.org/2014/106'),
    '(ps|mal)-(rep-field|shamir)': 'AN17',
    'mascot': 'KOS16',
    'mama': 'mascot',
    'mal-ccd': ('mal-shamir', 'CCD88'),
    'mal-rep-bin': 'https://eprint.iacr.org/2016/944',
    'mal-rep-ring': 'EKOPPS20',
    'rep4.*': 'https://eprint.iacr.org/2020/1330',
    '^rep-field': 'AFLNO16',
    'replicated': 'AFLNO16',
    '^ring': ('Keller25', 'AFLNO16'),
    'ps-rep-bin': 'https://doi.org/10.1109/SP.2017.15',
    'ps-rep-(ring|field)': 'EKOPPS20',
    'semi.*': ('KOS16', 'Keller20'),
    '^shamir': 'https://eprint.iacr.org/2000/037',
    'spdz2k': 'https://eprint.iacr.org/2018/482',
    'soho': ('KPR17', 'Keller20'),
    'temi': ('hemi', 'https://eprint.iacr.org/2000/055'),
    'sy.*': 'https://eprint.iacr.org/2018/570',
    'sy-rep-ring': 'https://eprint.iacr.org/2019/1298',
    'tinier': 'https://eprint.iacr.org/2015/901',
    'tiny': ('spdz2k', 'https://eprint.iacr.org/2016/944'),
    'trio': 'Keller25',
    'yao': ('https://eprint.iacr.org/2014/756',
            'https://eprint.iacr.org/2019/1168')
}

def reading_for_protocol(protocol):
    if not protocol:
        return
    if 'http' in protocol:
        return protocol
    paper = protocol_papers.get(protocol)
    if not paper:
        for x, y in protocol_papers.items():
            if re.search(x, protocol):
                paper = y
                break
        if re.match('[A-Z]', protocol):
            paper = protocol
    if isinstance(paper, tuple):
        paper = ', '.join(reading_for_protocol(x) for x in paper)
    return papers.get(paper) or reading_for_protocol(paper) or paper
