// CWE: CWE-1300
module simple_encryption(clk, rst, start, data_in, key, data_out, done);
    input wire          clk;
    input wire          rst;
    input wire          start;
    input wire [63:0]   data_in;
    input wire [63:0]   key;
    output reg [63:0]   data_out;
    output reg          done;

    reg [63:0] internal_key;
    reg [63:0] internal_data;
    reg [3:0]  state;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            internal_key <= 64'h0;
            internal_data <= 64'h0;
            data_out <= 64'h0;
            done <= 1'b0;
            state <= 4'd0;
        end else begin
            case (state)
                4'd0: begin
                    if (start) begin
                        internal_key <= key; // Key is directly stored without obfuscation
                        internal_data <= data_in;
                        state <= 4'd1;
                    end
                end
                4'd1: begin
                    internal_data <= internal_data ^ internal_key; // Simple XOR encryption
                    state <= 4'd2;
                end
                4'd2: begin
                    data_out <= internal_data;
                    done <= 1'b1;
                    state <= 4'd3;
                end
                4'd3: begin
                    done <= 1'b0;
                    state <= 4'd0;
                end
            endcase
        end
    end
endmodule