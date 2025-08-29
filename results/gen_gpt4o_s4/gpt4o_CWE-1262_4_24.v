// CWE: CWE-1262
module secure_data_module(
    input wire clk,
    input wire rst,
    input wire [31:0] data_in,
    input wire write_enable,
    input wire [31:0] write_data,
    output wire [31:0] data_out
);

reg [31:0] sensitive_data_reg;

// Unprotected write to sensitive register
always @(posedge clk) begin
    if (rst) begin
        sensitive_data_reg <= 32'h0;
    end else if (write_enable) begin
        sensitive_data_reg <= write_data; // Vulnerability: Allows software access to sensitive data
    end else begin
        sensitive_data_reg <= data_in;
    end
end

assign data_out = sensitive_data_reg;

endmodule