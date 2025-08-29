// CWE: CWE-440
module data_processor (clk, rst, data_in, data_out);
    input clk;
    input rst;
    input [15:0] data_in;
    output reg [15:0] data_out;

    reg [7:0] lookup_table [0:255];

    initial begin
        lookup_table[8'h00] = 8'h00; // Incorrect: should be 8'h63
        lookup_table[8'h01] = 8'h01; // Incorrect: should be 8'h7c
        lookup_table[8'h02] = 8'h77;
        lookup_table[8'h03] = 8'h7b;
        lookup_table[8'h04] = 8'hf2;
        lookup_table[8'h05] = 8'h6b;
        lookup_table[8'h06] = 8'h6f;
        lookup_table[8'h07] = 8'hc5;
        lookup_table[8'h08] = 8'h30;
        lookup_table[8'h09] = 8'h01;
        // ... (rest of the table)
        lookup_table[8'hff] = 8'h16;
    end

    always @ (posedge clk or posedge rst) begin
        if (rst)
            data_out <= 16'd0;
        else
            data_out <= {lookup_table[data_in[15:8]], lookup_table[data_in[7:0]]};
    end
endmodule