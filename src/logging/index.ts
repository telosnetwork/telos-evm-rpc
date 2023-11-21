export default class Logger {

    debugEnabled : boolean;

    constructor(debugEnabled:boolean){
        if (debugEnabled) {
            this.debugEnabled = true;
        }else{
            this.debugEnabled = false;
        }
    }

    /**
    * Adds an element to a bit vector of a 64 byte bloom filter.
    * @param s - The string to console log
    */
    debug(s: string, ) {
      if (this.debugEnabled == true) {
        console.log(s);
      }
    }
    log(s: string, ) {
        console.log(s);
    }

    error(s: any) {
        console.error(s);
    }
}
