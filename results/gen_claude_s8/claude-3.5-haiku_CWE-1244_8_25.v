// CWE: CWE-1244
module debug_sensitive_register_file (
    input wire clk,
    input wire rst,
    input wire [7:0] write_addr,
    input wire [31:0] write_data,
    input wire write_enable,
    input wire debug_mode,
    output wire [31:0] read_data,
    output wire [31:0] debug_register_contents
);
    reg [31:0] registers [0:255];
    reg [31:0] sensitive_register;

    // Unsafe debug access - expose entire sensitive register contents
    assign debug_register_contents = sensitive_register;

    always @(posedge clk) begin
        if (rst) begin
            sensitive_register <= 32'hDEADBEEF;  // Initial sensitive value
        end else if (debug_mode) begin
            // Unrestricted write access in debug mode
            sensitive_register <= write_data;
        end
    end

    always @(posedge clk) begin
        if (write_enable && !debug_mode) begin
            registers[write_addr] <= write_data;
        end
    end

    assign read_data = registers[write_addr];

endmodule