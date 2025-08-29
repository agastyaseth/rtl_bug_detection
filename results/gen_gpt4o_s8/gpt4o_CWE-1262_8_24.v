// CWE: CWE-1262
module secure_data_module (
    input wire clk,
    input wire rst,
    input wire [31:0] data_in,
    input wire write_enable,
    output wire [31:0] data_out
);

reg [31:0] sensitive_data_reg;

always @(posedge clk) begin
    if (rst) begin
        sensitive_data_reg <= 32'h0;
    end else if (write_enable) begin
        sensitive_data_reg <= data_in; // Unprotected write
    end
end

assign data_out = sensitive_data_reg;

endmodule