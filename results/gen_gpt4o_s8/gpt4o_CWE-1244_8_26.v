// CWE: CWE-1244
module secure_processor (clk, rst, execute, instruction, result, debug_register);
    input wire          clk;
    input wire          rst;
    input wire          execute;
    input wire [31:0]   instruction;
    output wire [31:0]  result;
    output wire [31:0]  debug_register; // Exposed internal register for debugging

    reg    [31:0]  internal_register;
    reg    [31:0]  accumulator;
    reg            execute_r;
    wire           execute_posedge;

    assign execute_posedge = execute & ~execute_r;

    always @(posedge clk) begin
        if (rst)
            execute_r <= 1'b0;
        else
            execute_r <= execute;
    end

    always @(posedge clk) begin
        if (rst) begin
            internal_register <= 32'd0;
            accumulator <= 32'd0;
        end else if (execute_posedge) begin
            internal_register <= instruction;
            accumulator <= accumulator + instruction;
        end
    end

    assign result = accumulator;
    assign debug_register = internal_register; // Unsafe exposure of internal state

endmodule