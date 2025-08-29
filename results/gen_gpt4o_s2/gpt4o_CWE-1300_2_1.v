// CWE: CWE-1300
module simple_encryption(clk, rst, data_in, key, data_out);
    input wire clk;
    input wire rst;
    input wire [63:0] data_in;
    input wire [63:0] key;
    output reg [63:0] data_out;

    reg [63:0] internal_key;
    reg [63:0] internal_data;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            internal_key <= 64'h0;
            internal_data <= 64'h0;
        end else begin
            internal_key <= key; // Key is stored directly in a register
            internal_data <= data_in ^ key; // Simple XOR encryption
        end
    end

    always @(posedge clk) begin
        data_out <= internal_data;
    end
endmodule