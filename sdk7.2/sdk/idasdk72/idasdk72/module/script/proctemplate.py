# ----------------------------------------------------------------------
# Processor module template script
# (c) Hex-Rays
import sys
import idaapi
from idaapi import *

retcode_0 = 0xC3
retcode_1 = 0xC2
g_retcodes = [retcode_0, retcode_1]

# ----------------------------------------------------------------------
class sample_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    The required and optional attributes/callbacks are illustrated in this template
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['myproc']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['My processor module']

    # register names
    reg_names = [
        # General purpose registers
        "SP", # aka R0
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
        "R7",
        # VM registers
        "FLAGS", # 0
        "IP",    # 1
        "VM2",
        "VM3",
        "VM4",
        "VM5",
        "VM6",
        "VM7",
        # Fake segment registers
        "CS",
        "DS"
    ]

    # number of registers (optional: deduced from the len(reg_names))
    regs_num = len(reg_names)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    reg_first_sreg = 16 # index of CS
    reg_last_sreg  = 17 # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    reg_code_sreg = 16
    reg_data_sreg = 17

    # Array of typical code start sequences (optional)
    codestart = ['\x55\x8B', '\x50\x51']

    # Array of 'return' instruction opcodes (optional)
    retcodes = g_retcodes

    # Array of instructions. Since this is only a template,
    # this list will be extremely limited.
    instruc = [
        {'name': 'ADD', 'feature': CF_USE1 | CF_CHG1 | CF_USE2}, # ADD <reg>, <#imm> -- opcodes [0x00 -> 0x7F]
        {'name': 'MOV', 'feature': CF_USE1 | CF_CHG1 | CF_USE2}, # MOV <reg>, <reg> -- opcodes [0x80 -> 0xEF] (but retcodes)
        {'name': 'RET', 'feature': 0}, # RET -- opcodes 0xC2, 0xC3
        {'name': 'JMP', 'feature': CF_USE1 | CF_JUMP}, # JMP -- opcodes [0xF0 -> 0xFF]
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = 5

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "My processor module bytecode assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # remove if not allowed
        'a_yword': "ymmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler

    def regname2index(self, regname):
        for idx in xrange(len(self.reg_names)):
            if regname == self.reg_names[idx]:
                return idx
        return -1


    # ----------------------------------------------------------------------
    # The following callbacks are optional.
    # *** Please remove the callbacks that you don't plan to implement ***

    def notify_out_header(self, ctx):
        """function to produce start of disassembled text"""
        pass

    def notify_out_footer(self, ctx):
        """function to produce end of disassembled text"""
        pass

    def notify_out_segstart(self, ctx, ea):
        """function to produce start of segment"""
        pass

    def notify_out_segend(self, ctx, ea):
        """function to produce end of segment"""
        pass

    def notify_out_assumes(self, ctx):
        """function to produce assume directives"""
        pass

    def notify_term(self):
        """called when the processor module is unloading"""
        pass

    def notify_setup_til(self):
        """Setup default type libraries (called after loading a new file into the database)
        The processor module may load tils, setup memory model and perform other actions required to set up the type system
        @return: None
        """
        pass

    def notify_newprc(self, nproc, keep_cfg):
        """
        Before changing proccesor type
        nproc - processor number in the array of processor names
        return >=0-ok,<0-prohibit
        """
        return 0

    def notify_newfile(self, filename):
        """A new file is loaded (already)"""
        pass

    def notify_oldfile(self, filename):
        """An old file is loaded (already)"""
        pass

    def notify_newbinary(self, filename, fileoff, basepara, binoff, nbytes):
        """
        Before loading a binary file
         args:
          filename  - binary file name
          fileoff   - offset in the file
          basepara  - base loading paragraph
          binoff    - loader offset
          nbytes    - number of bytes to load
        Returns nothing
        """
        pass

    def notify_undefine(self, ea):
        """
        An item in the database (insn or data) is being deleted
        @param args: ea
        @return: >=0-ok, <0 - the kernel should stop
                 if the return value is not negative:
                     bit0 - ignored
                     bit1 - do not delete srareas at the item end
        """
        return 1

    def notify_endbinary(self, ok):
        """
         After loading a binary file
         args:
          ok - file loaded successfully?
        """
        pass

    def notify_assemble(self, ea, cs, ip, use32, line):
        """
        Assemble an instruction
         (make sure that PR_ASSEMBLE flag is set in the processor flags)
         (display a warning if an error occurs)
         args:
           ea -  linear address of instruction
           cs -  cs of instruction
           ip -  ip of instruction
           use32 - is 32bit segment?
           line - line to assemble
        returns the opcode string
        """
        pass

    def notify_savebase(self):
        """The database is being saved. Processor module should save its local data"""
        pass

    def notify_out_data(self, ctx, analyze_only):
        """
        Generate text represenation of data items
        This function MAY change the database and create cross-references, etc.
        """
        ctx.out_data(analyze_only)

    def notify_cmp_opnd(self, op1, op2):
        """
        Compare instruction operands.
        Returns 1-equal,0-not equal operands.
        """
        return False

    def notify_can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return True

    def translate(self, base, offset):
        """
        Translation function for offsets
        Currently used in the offset display functions
        to calculate the referenced address
        Returns: ea_t
        """
        return BADADDR

    def notify_set_idp_options(self, keyword, type, value):
        """
        Set IDP-specific option
        args:
          keyword - the option name
                    or empty string (check type when 0 below)
          type    - one of
                      IDPOPT_STR  string constant
                      IDPOPT_NUM  number
                      IDPOPT_BIT  zero/one
                      IDPOPT_I64  64bit number
                      0 -> You should display a dialog to configure the processor module
          value   - the actual value
        Returns:
           IDPOPT_OK        ok
           IDPOPT_BADKEY    illegal keyword
           IDPOPT_BADTYPE   illegal type of value
           IDPOPT_BADVALUE  illegal value (bad range, for example)
        otherwise return a string containing the error messages
        """
        return idaapi.IDPOPT_OK

    def notify_gen_map_file(self, qfile):
        """
        Generate map file. If this function is absent then the kernel will create the map file.
        This function returns number of lines in output file.
        0 - empty file, -1 - write error
        """
        r1 = qfile.write("Line 1\n")
        r2 = qfile.write("Line 2\n!")
        return 2 # two lines

    def notify_create_func_frame(self, func_ea):
        """
        Create a function frame for a newly created function.
        Set up frame size, its attributes etc.
        """
        return False

    def notify_is_far_jump(self, icode):
        """
        Is indirect far jump or call instruction?
        meaningful only if the processor has 'near' and 'far' reference types
        """
        return False

    def notify_is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return 0

    def notify_out_special_item(self, ctx, segtype):
        """
        Generate text representation of an item in a special segment
        i.e. absolute symbols, externs, communal definitions etc.
        Returns: 1-overflow, 0-ok
        """
        return 0

    def notify_get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
             4 bytes for 32-bit function
             2 bytes otherwise
        """
        return 2

    def notify_is_switch(self, swi, insn):
        """
        Find 'switch' idiom at instruction 'insn'.
        Fills 'swi' structure with information

        @return: Boolean (True if switch was found and False otherwise)
        """
        return False

    def notify_is_sp_based(self, insn, op):
        """
        Check whether the operand is relative to stack pointer or frame pointer.
        This function is used to determine how to output a stack variable
        This function may be absent. If it is absent, then all operands
        are sp based by default.
        Define this function only if some stack references use frame pointer
        instead of stack pointer.
        returns flags:
          OP_FP_BASED   operand is FP based
          OP_SP_BASED   operand is SP based
          OP_SP_ADD     operand value is added to the pointer
          OP_SP_SUB     operand value is substracted from the pointer
        """
        return idaapi.OP_FP_BASED

    def notify_add_func(self, func_ea):
        """
        The kernel has added a function.
        @param func_ea: function start EA
        @return: Nothing
        """
        pass

    def notify_del_func(self, func_ea):
        """
        The kernel is about to delete a function
        @param func_ea: function start EA
        @return: 0-ok,<0-do not delete
        """
        return 0

    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        return "comment for %d" % insn.itype

    def notify_create_switch_xrefs(self, jumpea, swi):
        """Create xrefs for a custom jump table
           @param jumpea: address of the jump insn
           @param swi: switch information
           @return: None
        """
        pass

    def notify_calc_step_over(self, ip):
        """
        Calculate the address of the instruction which will be
        executed after "step over". The kernel will put a breakpoint there.
        If the step over is equal to step into or we can not calculate
        the address, return BADADDR.
        args:
          ip - instruction address
        returns: target or BADADDR
        """
        return idaapi.BADADDR

    def notify_may_be_func(self, insn, state):
        """
        can a function start here?
        the instruction is in 'insn'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        return 0

    def notify_str2reg(self, regname):
        """
        Convert a register name to a register number
          args: regname
          Returns: register number or -1 if not avail
          The register number is the register index in the reg_names array
          Most processor modules do not need to implement this callback
          It is useful only if ph.reg_names[reg] does not provide
          the correct register names
        """
        r = self.regname2index(regname)
        if r < 0:
            return -1
        else:
            return r

    def notify_is_sane_insn(self, insn, no_crefs):
        """
        is the instruction sane for the current file type?
        args: no_crefs
        1: the instruction has no code refs to it.
           ida just tries to convert unexplored bytes
           to an instruction (but there is no other
           reason to convert them into an instruction)
        0: the instruction is created because
           of some coderef, user request or another
           weighty reason.
        The instruction is in 'insn'
        returns: >=0-ok, <0-no, the instruction isn't
        likely to appear in the program
        """
        return -1

    def notify_func_bounds(self, code, func_ea, max_func_end_ea):
        """
        find_func_bounds() finished its work
        The module may fine tune the function bounds
        args:
          possible code - one of FIND_FUNC_XXX (check find_func_bounds)
          func_ea - func start ea
          max_func_end_ea (from the kernel's point of view)
        returns: possible_return_code
        """
        return FIND_FUNC_OK

    def asm_out_func_header(self, ctx, func_ea):
        """generate function header lines"""
        pass

    def asm_out_func_footer(self, ctx, func_ea):
        """generate function footer lines"""
        pass

    def asm_get_type_name(self, flag, ea_or_id):
        """
        Get name of type of item at ea or id.
        (i.e. one of: byte,word,dword,near,far,etc...)
        """
        if is_code(flag):
            pfn = get_func(ea_or_id)
            # return get func name
        elif is_word(flag):
            return "word"
        return ""

    def notify_init(self, idp_file):
        # init returns >=0 on success
        return 0

    def notify_out_label(self, ctx, label):
        """
        The kernel is going to generate an instruction label line
        or a function header.
        args:
          ctx - output context
          label - label to output
        If returns value <0, then the kernel should not generate the label
        """
        return 0

    def notify_rename(self, ea, new_name):
        """
        The kernel is going to rename a byte
        args:
          ea -
          new_name -
        If returns value <0, then the kernel should not rename it
        """
        return 0

    def notify_may_show_sreg(self, ea):
        """
        The kernel wants to display the segment registers
        in the messages window.
        args:
          ea
        if this function returns <0
        then the kernel will not show
        the segment registers.
        (assuming that the module have done it)
        """
        return 0

    def notify_coagulate(self, start_ea):
        """
        Try to define some unexplored bytes
        This notification will be called if the
        kernel tried all possibilities and could
        not find anything more useful than to
        convert to array of bytes.
        The module can help the kernel and convert
        the bytes into something more useful.
        args:
          start_ea -
        returns: number of converted bytes
        """
        return 0

    def notify_closebase(self):
        """
        The database will be closed now
        """
        pass

    def notify_load_idasgn(self, short_sig_name):
        """
        FLIRT signature have been loaded for normal processing
        (not for recognition of startup sequences)
        args:
          short_sig_name
        """
        pass

    def notify_auto_empty(self):
        """
        Info: all analysis queues are empty.
        This callback is called once when the
        initial analysis is finished. If the queue is
        not empty upon the return from this callback,
        it will be called later again
        """
        pass

    def notify_is_call_insn(self, insn):
        """
        Is the instruction a "call"?
        args
          insn  - instruction
        returns: 0-unknown, <0-no, 1-yes
        """
        return 0

    def notify_is_ret_insn(self, insn, strict):
        """
        Is the instruction a "return"?
        insn  - instruction
        strict - 1: report only ret instructions
                 0: include instructions like "leave"
                    which begins the function epilog
        returns: 0-unknown, <0-no, 1-yes
        """
        return 0

    def notify_kernel_config_loaded(self):
        """
        This callback is called when ida.cfg is parsed
        """
        pass

    def notify_is_alloca_probe(self, ea):
        """
        Does the function at 'ea' behave as __alloca_probe?
        args:
          ea
        returns: 1-yes, 0-false
        """
        return 0

    def notify_gen_src_file_lnnum(self, ctx, filename, lnnum):
        """
        Callback: generate analog of
        #line "file.c" 123
        directive.
        args:
          ctx   - output context
          file  - source file (may be NULL)
          lnnum - line number
        returns: 1-directive has been generated
        """
        return 0

    def notify_is_insn_table_jump(self, insn):
        """
        Callback: determine if instruction is a table jump or call
        If CF_JUMP bit can not describe all kinds of table
        jumps, please define this callback.
        It will be called for insns with CF_JUMP bit set.
        input: insn structure contains the current instruction
        returns: 0-yes, <0-no
        """
        return -1

    def notify_auto_empty_finally(self):
        """
        Info: all analysis queues are empty definitively
        """
        pass

    def notify_is_indirect_jump(self, insn):
        """
        Callback: determine if instruction is an indrect jump
        If CF_JUMP bit can not describe all jump types
        jumps, please define this callback.
        input: insn structure contains the current instruction
        returns: 0-use CF_JUMP, 1-no, 2-yes
        """
        return 0

    def notify_determined_main(self, main_ea):
        """
        The main() function has been determined
        """
        pass

    def notify_validate_flirt_func(self, ea, funcname):
        """
        flirt has recognized a library function
        this callback can be used by a plugin or proc module
        to intercept it and validate such a function
        args:
          start_ea
          funcname
        returns: -1-do not create a function,
                  0-function is validated
        """
        return 0

    def notify_set_proc_options(self, options, confidence):
        """
        called if the user specified an option string in the command line:
        -p<processor name>:<options>
        can be used for e.g. setting a processor subtype
        also called if option string is passed to set_processor_type()
        and IDC's set_processor_type()
        args:
          options
          confidence - 0: loader's suggestion,
                       1: user's decision
        returns: <0 - bad option string
        """
        return 0

    def notify_creating_segm(self, start_ea, segm_name, segm_class):
        """
        A new segment is about to be created
        args:
          start_ea
          segm_name
          segm_class
        return >=0-ok, <0-segment should not be created
        """
        return 0

    def notify_auto_queue_empty(self, type):
        """
        One analysis queue is empty.
        args:
          atype_t type
        This callback can be called many times, so
        only the auto_mark() functions can be used from it
        (other functions may work but it is not tested)
        """
        return 1

    def notify_gen_regvar_def(self, ctx, canon, user, cmt):
        """
        generate register variable definition line
        args:
          ctx   - output context
          canon - canonical register name (case-insensitive)
          user  - user-defined register name
          cmt   - comment to appear near definition
        returns: >0-ok
        """
        return 0

    def notify_setsgr(self, start_ea, end_ea, regnum, value, old_value, tag):
        """
        The kernel has changed a segment register value
        args:
          start_ea
          end_ea
          regnum
          value
          old_value
          uchar tag (SR_... values)
        returns: 0-ok, <0-error
        """
        return 0

    def notify_set_compiler(self):
        """
        The kernel has changed the compiler information
        """
        pass

    def notify_is_basic_block_end(self, insn, call_insn_stops_block):
        """
        Is the current instruction end of a basic block?
        This function should be defined for processors
        with delayed jump slots. The current instruction
        is stored in 'insn'
        args:
          call_insn_stops_block
          returns: 0-unknown, -1-no, 1-yes
        """
        return 0

    def notify_make_code(self, insn):
        """
        An instruction is being created
        args:
          insn
        returns: 0-ok, <0-the kernel should stop
        """
        return 0

    def notify_make_data(self, ea, flags, tid, size):
        """
        A data item is being created
        args:
          ea
          flags
          tid
          size
        returns: 0-ok, <0-the kernel should stop
        """
        return 0

    def notify_moving_segm(self, start_ea, segm_name, segm_class, to_ea, flags):
        """
        May the kernel move the segment?
        args:
          start_ea, segm_name, segm_class - segment to move
          to_ea   - new segment start address
          int flags - combination of MSF_... bits
        returns: 0-yes, <0-the kernel should stop
        """
        return 0

    def notify_move_segm(self, from_ea, start_ea, segm_name, segm_class, changed_netdelta):
        """
        A segment is moved
        Fix processor dependent address sensitive information
        args:
          from_ea  - old segment address
          start_ea, segm_name, segm_class - moved segment
          changed_netdelta - if ea-to-netnode mapping has been changed
        returns: nothing
        """
        pass

    def notify_verify_noreturn(self, func_start_ea):
        """
        The kernel wants to set 'noreturn' flags for a function
        args:
          func_start_ea
        Returns: 0-ok, <0-do not set 'noreturn' flag
        """
        return 0

    def notify_verify_sp(self, func_start_ea):
        """
        All function instructions have been analyzed
        Now the processor module can analyze the stack pointer
        for the whole function
        args:
          func_start_ea
        Returns: 0-ok, <0-bad stack pointer
        """
        return 0

    def notify_renamed(self, ea, new_name, is_local_name):
        """
        The kernel has renamed a byte
        args:
          ea
          new_name
          is_local_name
        Returns: nothing. See also the 'rename' event
        """
        pass

    def notify_set_func_start(self, pfn, new_ea):
        """
        Function chunk start address will be changed
        args:
          pfn
          new_ea
        Returns: 0-ok,<0-do not change
        """
        return 0

    def notify_set_func_end(self, pfn, new_end_ea):
        """
        Function chunk end address will be changed
        args:
          pfn
          new_end_ea
        Returns: 0-ok,<0-do not change
        """
        return 0

    def notify_treat_hindering_item(self, hindering_item_ea, new_item_flags, new_item_ea, new_item_length):
        """
        An item hinders creation of another item
        args:
          hindering_item_ea
          new_item_flags
          new_item_ea
          new_item_length
        Returns: 0-no reaction, <0-the kernel may delete the hindering item
        """
        return 0

    def notify_get_operand_string(self, insn, opnum):
        """
        Request text string for operand (cli, java, ...)
        args:
          insn - the instruction
          opnum - the operand number; -1 means any string operand
        Returns: requested
        """
        return ""

    def notify_coagulate_dref(self, from_ea, to_ea, may_define, code_ea):
        """
        data reference is being analyzed
        args:
          from_ea, to_ea, may_define, code_ea
        plugin may correct code_ea (e.g. for thumb mode refs, we clear the last bit)
        Returns: new code_ea or -1 - cancel dref analysis
        """
        return 0

    # ----------------------------------------------------------------------
    # The following callbacks are mandatory
    #

    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        if insn.itype == 4: # JMP
            add_cref(insn.ea, insn.Op1.addr, fl_JN)
        elif insn.itype != 2: # 2 == RET, 4 == JMP
            add_cref(insn.ea, insn.ea + insn.size, fl_F)
        return 1

    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        if op.type == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif op.type == o_imm:
            ctx.out_value(op, OOFW_IMM)
        elif op.type == o_near:
            ctx.out_name_expr(op, op.addr, BADADDR)
        else:
            return False

        return True

    def notify_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()

        for i in xrange(0, 2):
            op = ctx.insn[i]
            if op.type == o_void:
                break;
            if i > 0:
                ctx.out_symbol(',')
                ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()

    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        b = insn.get_next_byte()
        if b < 0x80:              # ADD
            insn.itype = 0
            insn.Op1.type = o_reg
            insn.Op1.reg = b & 0xF
            insn.Op2.type = o_imm
            insn.Op2.dtype = dt_byte
            insn.Op2.value = (b >> 4) & 0xF
        elif b in g_retcodes:     # RET
            insn.itype = 2
        elif b < 0xF0:            # MOV
            insn.itype = 1
            insn.Op1.type = o_reg
            insn.Op1.reg = b & 0xF
            insn.Op2.type = o_reg
            insn.Op2.value = (b >> 4) & 0xF
        else:
            insn.itype = 3
            insn.Op1.type = o_near
            insn.Op1.dtype = dt_dword
            insn.Op1.addr = insn.ea + (b & 0xF)

        # Return decoded instruction size or zero
        return insn.size

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return sample_processor_t()
