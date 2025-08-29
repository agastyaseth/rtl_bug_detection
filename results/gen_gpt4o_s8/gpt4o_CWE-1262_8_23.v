// CWE: CWE-1262
module sensitive_data_exposure(
    input wire clk,
    input wire rst,
    input wire [31:0] data_in,
    input wire write_enable,
    output wire [31:0] data_out
);

reg [31:0] sensitive_reg;

always @(posedge clk) begin
    if (rst) begin
        sensitive_reg <= 32'h0;
    end else if (write_enable) begin
        sensitive_reg <= data_in; // Unprotected write to sensitive register
    end
end

assign data_out = sensitive_reg; // Exposing sensitive data

endmodule