// CWE: CWE-1300
module secure_storage(clk, rst, write_enable, data_in, data_out);
    input wire clk;
    input wire rst;
    input wire write_enable;
    input wire [127:0] data_in;
    output reg [127:0] data_out;

    reg [127:0] secret_key; // Secret key stored directly in a register

    always @(posedge clk) begin
        if (rst) begin
            secret_key <= 128'hDEADBEEFDEADBEEFDEADBEEFDEADBEEF; // Hardcoded key
            data_out <= 128'b0;
        end else if (write_enable) begin
            secret_key <= data_in; // Key can be overwritten
        end else begin
            data_out <= secret_key; // Key is directly outputted
        end
    end
endmodule