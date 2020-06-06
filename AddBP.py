import idautils
import idaapi
import idc
#import tempfile


class AddBreakPoint:
    def __init__(self, addr, condition="", elang = "Python"):
        """
        :param addr: String type, 32 bit address
        :param condition: Condition type object
        :return:
        """
        self.address = addr
        self.condition = condition
        self.elang = elang

    def set(self, break_p=False):
        #print "breakpoint on %08x" % self.address
        idaapi.add_bpt(self.address, 0, idc.BPT_SOFT)
        idaapi.enable_bpt(self.address, True)
        #idc.SetBptCnd(self.address, self.condition.get_text())
        bpt = idaapi.bpt_t()
        idaapi.get_bpt(self.address, bpt)
        bpt.elang = self.elang
        bpt.condition = self.condition.get_text()
        idaapi.update_bpt(bpt)

    def delete(self):
        idaapi.del_bpt(self.address)


class Condition:
    def __init__(self, type, cond_text = ''):
        """
        the types of conditions are;
        get_return_address - 0
        :return: a condition for bp
        """
        self.__enum_type = {0: "get_return_address", 7: "debug"}
        self.type = type if type in self.__enum_type.keys() else 3
        self.name = self.__enum_type[self.type]
        self.text = cond_text
        self.__set_start_text()

    def __set_start_text(self):
        if self.type == 0:
            self.text = """auto addr = get_screen_ea();
            "gal" == "IDA";\
            """
        if self.type == 2:
            self.text = """get_reg_value("eax");
            """
        elif self.type == 1:
            self.text = """
                        "gal" == "IDA";
                        """
        elif self.type == 7:
            pass
        else:  # empty
            self.text = ""
        return 0

    def recursive_conditinal_breakpoint(self):
        return 0

    def get_text(self):
        return self.text


def define_function_trace(adr):
    return idc.set_bpt_attr(adr, idc.BPTATTR_FLAGS, idc.BPT_ENABLED | idc.BPT_TRACE | idc.BPT_TRACEON | idc.BPT_TRACE_FUNC) #idc.BPT_BRK |


def delete_bp(adr):
    idaapi.del_bpt(adr)


def get_bpt(adr):
    """
    :param adr: the bp address
    :return: the bpt_t object of the breakpoint in the address
    """
    bpt = idaapi.bpt_t()
    idaapi.get_bpt(adr, bpt)
    return bpt




def add(ea, cond_user=''):
    """
    :param ea: Address of the breakpoint
    :param cond_user: break point condition
    :return: not relevant
    """
    if cond_user == '':
        cond = Condition(0)
    else:
        cond = Condition(7, cond_user)
    hook = AddBreakPoint(ea, cond)
    hook.set()
    return hook

