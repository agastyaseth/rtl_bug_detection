// CWE: CWE-440
module expected_behavior_violation(clk, rst, data_in, data_out);
    input clk;
    input rst;
    input [7:0] data_in;
    output reg [7:0] data_out;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            data_out <= 8'h00;
        end else begin
            case (data_in)
                8'h00: data_out <= 8'hFF; // Incorrect: should be 8'h01
                8'h01: data_out <= 8'h00; // Incorrect: should be 8'h02
                8'h02: data_out <= 8'h02;
                8'h03: data_out <= 8'h03;
                8'h04: data_out <= 8'h04;
                8'h05: data_out <= 8'h05;
                8'h06: data_out <= 8'h06;
                8'h07: data_out <= 8'h07;
                8'h08: data_out <= 8'h08;
                8'h09: data_out <= 8'h09;
                8'h0A: data_out <= 8'h0A;
                8'h0B: data_out <= 8'h0B;
                8'h0C: data_out <= 8'h0C;
                8'h0D: data_out <= 8'h0D;
                8'h0E: data_out <= 8'h0E;
                8'h0F: data_out <= 8'h0F;
                default: data_out <= 8'hFF; // Fallback to an invalid value
            endcase
        end
    end
endmodule