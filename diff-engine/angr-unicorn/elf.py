from os.path import dirname, abspath, join
from elftools.elf.elffile import ELFFile


class ELFParseException(Exception):
    pass


def get_segments(elfpath):
    with open(elfpath, "rb") as f:
        elffile = ELFFile(f)
        data = []
        for segment in elffile.iter_segments():
            p_type = segment.header["p_type"]
            if p_type == "PT_LOAD":
                data.append(segment.data())
    return data


def get_template_segments(mode):
    root_path = dirname(dirname(abspath(__file__)))
    template_path = join(root_path, "real/template_{}".format(mode))
    return get_segments(template_path)


def parse_template(mode):
    root_path = dirname(dirname(abspath(__file__)))
    template_path = join(root_path, "real/template_{}".format(mode))
    with open(template_path, "rb") as f:
        elffile = ELFFile(f)
        symtab = elffile.get_section_by_name(".symtab")
        inst_location = symtab.get_symbol_by_name("inst_location")[0]
        inst_location = inst_location.entry["st_value"]
        for segment in elffile.iter_segments():
            if segment.header["p_type"] == "PT_LOAD":
                base_location = segment.header["p_vaddr"]
                break
        else:
            raise ELFParseException("no load segment")
        offset = inst_location - base_location
        f.seek(0)
        binary = f.read()
    return binary, offset


def get_locations(elfpath):
    with open(elfpath, "rb") as f:
        elffile = ELFFile(f)
        symtab = elffile.get_section_by_name(".symtab")
        inst_location = symtab.get_symbol_by_name("inst_location")[0]
        inst_location = inst_location.entry["st_value"]
        bkpt_location = symtab.get_symbol_by_name("bkpt_location")[0]
        bkpt_location = bkpt_location.entry["st_value"]
        for segment in elffile.iter_segments():
            if segment.header["p_type"] == "PT_LOAD":
                base_location = segment.header["p_vaddr"]
                break
        else:
            raise ELFParseException("no load segment")
    return (inst_location, bkpt_location, base_location)


def get_template_locations(mode):
    root_path = dirname(dirname(abspath(__file__)))
    template_path = join(root_path, "real/template_{}".format(mode))
    return get_locations(template_path)
