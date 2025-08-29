// CWE: CWE-1300
module simple_crypto(clk, rst, start, data_in, key, data_out, done);
    input wire          clk;
    input wire          rst;
    input wire          start;
    input wire [63:0]   data_in;
    input wire [127:0]  key;
    output reg [63:0]   data_out;
    output reg          done;

    reg [63:0]          internal_data;
    reg [127:0]         internal_key;
    reg                 start_r;
    wire                start_posedge;
    reg [3:0]           process_counter;

    assign start_posedge = start & ~start_r;

    always @(posedge clk) begin
        if (rst)
            start_r <= 1'b0;
        else
            start_r <= start;
    end

    always @(posedge clk) begin
        if (rst) begin
            internal_data <= 64'b0;
            internal_key <= 128'b0; // Key stored here, vulnerable to reverse engineering
            process_counter <= 4'b0;
            done <= 1'b0;
        end else if (start_posedge) begin
            internal_data <= data_in ^ key[127:64]; // Initial operation with key bits
            internal_key <= key; // Full key loaded into internal_key
            process_counter <= 4'd10;
            done <= 1'b0;
        end else if (process_counter > 0) begin
            process_counter <= process_counter - 1;
            if (process_counter == 1) begin
                data_out <= internal_data ^ internal_key[63:0]; // Final operation with key bits
                done <= 1'b1;
            end
        end
    end
endmodule